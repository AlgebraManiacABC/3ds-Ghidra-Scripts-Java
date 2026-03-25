// Rename vtable function entries depth-first through the class hierarchy.
// Uses typeinfo inheritance chain + vtable scan to assign proper names.
// @category RTTI
// @author Claude (for AlgebraManiacABC)

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.List;
import java.util.ArrayList;

public class RenameVTableFunctions extends GhidraScript {

    private static final int PTR_SIZE = 4;

    private Memory mem;
    private SymbolTable symTable;

    // typeinfo address -> class name (fully qualified)
    private final Map<Long, String> typeinfoToClassName = new HashMap<>();
    // class name -> parent class name (null for roots)
    private final Map<String, List<String>> parentMap = new HashMap<>();
    // class name -> list of child class names
    private final Map<String, List<String>> childrenMap = new HashMap<>();
    // class name -> list of sub-vtable slot lists (index 0 = primary, 1+ = secondary)
    private final Map<String, List<List<Long>>> allVtableSlots = new HashMap<>();
    // class name -> primary vtable slot values (list of raw pointer values)
    private final Map<String, List<Long>> vtableSlots = new HashMap<>();
    // class name -> address of first slot (address point)
    private final Map<String, Address> vtableAddressPoints = new HashMap<>();
    // class name -> Namespace object
    private final Map<String, Namespace> classNamespaces = new HashMap<>();

    // Set of all known typeinfo addresses
    private final Set<Long> typeinfoAddresses = new HashSet<>();
    // Address of __cxa_pure_virtual (with thumb bit masked)
    private long pureVirtualAddr = 0;
    // Vtable region bounds
    private long vtableRegionStart;
    private long vtableRegionEnd;

    // Track which classes have been processed
    private final Set<String> processed = new HashSet<>();

    // Cache of opened CRO programs (path -> Program)
    private final Map<String, Program> importedPrograms = new HashMap<>();

    // Counters
    private int renameCount = 0;
    private int skipCount = 0;
    private int pureVirtualCount = 0;

    // Entry classification
    private enum EntryType {
        OFFSET,         // offset-to-top, vbase, vcall, ...
        FUNC_PTR,       // points to executable code
        TYPEINFO_PTR,   // points to a known typeinfo struct
        VTT_ENTRY,      // points back into vtable region
        OTHER           // ???
    }

    @Override
    protected void run() throws Exception {
        mem = currentProgram.getMemory();
        symTable = currentProgram.getSymbolTable();

        // Step 1: Find __cxa_pure_virtual
        findPureVirtual();

        // Step 2: Get vtable region bounds
        Address startAddr = askAddress("Vtable Region Start",
                "Enter the start address of the vtable region:");
        Address endAddr = askAddress("Vtable Region End",
                "Enter the end address of the vtable region:");
        vtableRegionStart = startAddr.getOffset();
        vtableRegionEnd = endAddr.getOffset();

        // Step 3: Collect typeinfo data and build inheritance tree
        println("Building inheritance tree from typeinfo...");
        buildInheritanceTree();
        println("  Classes found: " + typeinfoToClassName.size());

        // Step 4: Scan vtable region and collect per-class slot data
        println("Scanning vtable region...");
        scanVtableRegion(startAddr, endAddr);
        println("  Classes with vtable data: " + vtableSlots.size());

        // Step 5: Collect namespace objects for renaming
        collectNamespaces();

        // Step 6: Process classes in topological order (Kahn's algorithm)
        // This ensures all parents are processed before any child,
        // handling diamond inheritance correctly.
        println("Processing classes in topological order...");

        // Compute in-degree (number of parents) for each class
        Map<String, Integer> inDegree = new HashMap<>();
        for (String className : typeinfoToClassName.values()) {
            inDegree.put(className, 0);
        }
        for (Map.Entry<String, List<String>> entry : parentMap.entrySet()) {
            inDegree.put(entry.getKey(), entry.getValue().size());
        }

        // Initialize queue with root classes (in-degree 0)
        java.util.ArrayDeque<String> queue = new java.util.ArrayDeque<>();
        for (Map.Entry<String, Integer> entry : inDegree.entrySet()) {
            if (entry.getValue() == 0) {
                queue.add(entry.getKey());
            }
        }
        println("  Root classes: " + queue.size());
        println("");

        println("=== RENAMING FUNCTIONS ===\n");

        while (!queue.isEmpty()) {
            String className = queue.poll();
            processClass(className);

            // Decrement in-degree of children; enqueue if all parents done
            List<String> children = childrenMap.get(className);
            if (children != null) {
                for (String child : children) {
                    int remaining = inDegree.get(child) - 1;
                    inDegree.put(child, remaining);
                    if (remaining == 0) {
                        queue.add(child);
                    }
                }
            }
        }

        // Step 7: Report any classes with vtable data that weren't reached
        int unreached = 0;
        for (String className : vtableSlots.keySet()) {
            if (!processed.contains(className)) {
                unreached++;
                if (unreached <= 20) {
                    println("UNREACHED: " + className +
                            " (parent: " + parentMap.getOrDefault(className, List.of()) + ")");
                }
            }
        }
        if (unreached > 20) {
            println("... and " + (unreached - 20) + " more unreached classes.");
        }

        println("\n=== SUMMARY ===");
        println("Functions renamed:      " + renameCount);
        println("Slots skipped (same):   " + skipCount);
        println("Pure virtual skipped:   " + pureVirtualCount);
        println("Unreached classes:      " + unreached);
    }

    private void findPureVirtual() throws Exception {
        // Search symbol table for __cxa_pure_virtual
        SymbolIterator iter = symTable.getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            if (sym.getName().equals("__cxa_pure_virtual")) {
                pureVirtualAddr = sym.getAddress().getOffset();
                println("Found __cxa_pure_virtual at 0x" +
                        Long.toHexString(pureVirtualAddr));
                return;
            }
        }

        // Not found — ask user
        Address addr = askAddress("__cxa_pure_virtual",
                "Could not find __cxa_pure_virtual symbol.\n" +
                        "Enter its address (0 to skip pure virtual detection):");
        pureVirtualAddr = addr.getOffset();
        if (pureVirtualAddr != 0) {
            println("Using __cxa_pure_virtual at 0x" +
                    Long.toHexString(pureVirtualAddr));
        } else {
            println("WARNING: No __cxa_pure_virtual address. " +
                    "Pure virtual slots will not be detected.");
        }
    }

    private boolean isPureVirtual(long funcPtr) {
        if (pureVirtualAddr == 0) return false;
        // Mask off thumb bit for comparison
        return (funcPtr & ~1L) == (pureVirtualAddr & ~1L);
    }

    private void buildInheritanceTree() throws Exception {
        // Find all typeinfo symbols in the current program
        collectTypeinfoSymbols(currentProgram);

        // Resolve parents for each typeinfo, following cross-module references
        for (Map.Entry<Long, String> entry :
                new ArrayList<>(typeinfoToClassName.entrySet())) {
            long tiAddr = entry.getKey();
            String className = entry.getValue();
            resolveParents(currentProgram, tiAddr, className);
        }

        // Release any opened CRO programs
        for (Map.Entry<String, Program> entry : importedPrograms.entrySet()) {
            Program prog = entry.getValue();
            if (prog != null && prog != currentProgram) {
                prog.release(this);
            }
        }
    }

    private void collectTypeinfoSymbols(Program program) {
        SymbolIterator iter = program.getSymbolTable().getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            if (!sym.getName().equals("typeinfo")) continue;

            Namespace ns = sym.getParentNamespace();
            if (ns == null || ns.isGlobal()) continue;

            long addr = sym.getAddress().getOffset();
            String className = ns.getName(true);

            // Avoid overwriting code.bin entries with CRO entries
            if (!typeinfoToClassName.containsKey(addr)) {
                typeinfoToClassName.put(addr, className);
                typeinfoAddresses.add(addr);
            }
        }
    }

    private void resolveParents(Program program, long tiAddr, String className)
            throws Exception {
        // Skip if already resolved
        if (parentMap.containsKey(className)) return;

        Memory progMem = program.getMemory();
        Listing progListing = program.getListing();
        Address addr = program.getAddressFactory()
                .getDefaultAddressSpace().getAddress(tiAddr);

        // Determine RTTI type from applied struct size
        String rttiType = null;
        Data data = progListing.getDataAt(addr);
        if (data != null) {
            int size = data.getLength();
            if (size == 8) {
                rttiType = "__class_type_info";
            } else if (size == 12) {
                rttiType = "__si_class_type_info";
            } else if (size >= 16) {
                rttiType = "__vmi_class_type_info";
            }
        }
        if (rttiType == null) {
            if (className.contains("vmi_class")) {
                rttiType = "__vmi_class_type_info";
            } else if (className.contains("si_class")) {
                rttiType = "__si_class_type_info";
            } else if (className.contains("class_type")) {
                rttiType = "__class_type_info";
            }
        }
        if (rttiType == null) {
            println("WARNING: Could not determine RTTI type for " +
                    className + " at " + addr + " in " + program.getName());
            return;
        }

        switch (rttiType) {
            case "__class_type_info" -> {
                // No parent
            }
            case "__si_class_type_info" -> resolveBaseType(program, addr.add(8), className);
            case "__vmi_class_type_info" -> {
                int baseCount = progMem.getInt(addr.add(12));
                for (int b = 0; b < baseCount; b++) {
                    resolveBaseType(program, addr.add(16 + b * 8L), className);
                }
            }
        }

    }

    private boolean isOnUnresolved(long addr) {
        Symbol sym = getSymbolAt(toAddr(addr));
        return sym.getName().equals("OnUnresolved");
    }

    private void resolveBaseType(Program program, Address baseFieldAddr,
                                 String childClassName) throws Exception {
        Memory progMem = program.getMemory();
        long basePtr = Integer.toUnsignedLong(progMem.getInt(baseFieldAddr));

        // Check if parent is already known
        String parentName = typeinfoToClassName.get(basePtr);
        if (parentName != null) {
            addParentChild(childClassName, parentName);
            return;
        }

        // Check for unresolved pointer (zero or OnUnresolved)
        if (basePtr == 0 || isOnUnresolved(basePtr)) {
            // Try cross-module resolution
            ExternalTypeinfoResult result =
                    resolveExternalTypeinfo(program, baseFieldAddr);
            if (result != null) {
                // Register the external class
                if (!typeinfoToClassName.containsKey(result.typeinfoAddr)) {
                    typeinfoToClassName.put(result.typeinfoAddr, result.className);
                    typeinfoAddresses.add(result.typeinfoAddr);
                }

                addParentChild(childClassName, result.className);

                // Recursively resolve the external class's parents
                resolveParents(result.program, result.typeinfoAddr,
                        result.className);
            } else {
                println("WARNING: Could not resolve external parent for " +
                        childClassName + " at " + baseFieldAddr);
            }
            return;
        }

        // Non-zero pointer that doesn't match any known typeinfo
        println("WARNING: Unknown base typeinfo pointer 0x" +
                Long.toHexString(basePtr) + " for " + childClassName);
    }

    private void addParentChild(String childName, String parentName) {
        parentMap.computeIfAbsent(childName, k -> new ArrayList<>())
                .add(parentName);
        childrenMap.computeIfAbsent(parentName, k -> new ArrayList<>())
                .add(childName);
    }

    private static class ExternalTypeinfoResult {
        Program program;
        long typeinfoAddr;
        String className;
    }

    private Program openCroProgram(String progPath) {
        if (importedPrograms.containsKey(progPath)) {
            return importedPrograms.get(progPath);
        }

        try {
            ProjectData projectData = state.getProject().getProjectData();
            DomainFile domainFile = projectData.getFile(progPath);
            if (domainFile == null) {
                println("WARNING: Could not find CRO program: " + progPath);
                importedPrograms.put(progPath, null);
                return null;
            }

            Program prog = (Program) domainFile.getDomainObject(
                    this, true, false, monitor);
            importedPrograms.put(progPath, prog);

            // Collect typeinfo symbols from this CRO
            collectTypeinfoSymbols(prog);

            println("Opened CRO: " + progPath +
                    " (" + typeinfoToClassName.size() + " total typeinfo)");
            return prog;
        } catch (Exception e) {
            println("ERROR: Could not open CRO program " +
                    progPath + ": " + e.getMessage());
            importedPrograms.put(progPath, null);
            return null;
        }
    }

    private ExternalTypeinfoResult resolveExternalTypeinfo(
            Program sourceProgram, Address refAddr) throws Exception {
        ReferenceManager refMgr = sourceProgram.getReferenceManager();
        Reference[] refs = refMgr.getReferencesFrom(refAddr);

        for (Reference ref : refs) {
            if (!(ref instanceof ExternalReference extRef)) continue;
            ExternalLocation extLoc = extRef.getExternalLocation();

            // Get the path to the CRO program
            ExternalManager exMan = sourceProgram.getExternalManager();
            Library imported = exMan.getExternalLibrary(extLoc.getLibraryName());
            if (imported == null) {
                throw new Exception("Imported library " + extLoc.getLibraryName() + "leads nowhere!");
            }
            String progPath = imported.getAssociatedProgramPath();
            if (progPath == null) continue;

            // Open or retrieve cached CRO program
            Program croProg = openCroProgram(progPath);
            if (croProg == null) continue;

            // Get the address in the CRO
            Address extAddr = extLoc.getAddress();
            if (extAddr == null) continue;

            // Translate to CRO's address space
            Address croAddr = croProg.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(extAddr.getOffset());

            // Look for a typeinfo symbol at this address in the CRO
            Symbol[] syms = croProg.getSymbolTable().getSymbols(croAddr);
            for (Symbol sym : syms) {
                if (sym.getName().equals("typeinfo")) {
                    Namespace ns = sym.getParentNamespace();
                    if (ns != null && !ns.isGlobal()) {
                        ExternalTypeinfoResult result =
                                new ExternalTypeinfoResult();
                        result.program = croProg;
                        result.typeinfoAddr = croAddr.getOffset();
                        result.className = ns.getName(true);
                        return result;
                    }
                }
            }

            // Fallback: try reading the name pointer to find the class name
            try {
                Memory croMem = croProg.getMemory();
                long namePtr = Integer.toUnsignedLong(
                        croMem.getInt(croAddr.add(4)));
                Address namePtrAddr = croProg.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(namePtr);
                Symbol[] nameSyms = croProg.getSymbolTable()
                        .getSymbols(namePtrAddr);
                for (Symbol sym : nameSyms) {
                    Namespace ns = sym.getParentNamespace();
                    if (ns != null && !ns.isGlobal()) {
                        ExternalTypeinfoResult result =
                                new ExternalTypeinfoResult();
                        result.program = croProg;
                        result.typeinfoAddr = croAddr.getOffset();
                        result.className = ns.getName(true);
                        return result;
                    }
                }
            } catch (Exception e) {
                println("WARNING: Could not read CRO typeinfo at " +
                        croAddr + " in " + progPath);
            }
        }
        return null;
    }

    private void scanVtableRegion(Address startAddr, Address endAddr) throws Exception {
        // First pass: classify all entries and find RTTI slots
        List<Address> entryAddrs = new ArrayList<>();
        List<Long> entryValues = new ArrayList<>();
        List<EntryType> entryClasses = new ArrayList<>();

        Address current = startAddr;
        while (current.getOffset() <= endAddr.getOffset() - PTR_SIZE) {
            long value = Integer.toUnsignedLong(mem.getInt(current));
            EntryType cls = classifyEntry(value);

            entryAddrs.add(current);
            entryValues.add(value);
            entryClasses.add(cls);

            current = current.add(PTR_SIZE);
        }

        // Find all RTTI slot indices
        List<Integer> rttiIndices = new ArrayList<>();
        for (int i = 0; i < entryClasses.size(); i++) {
            if (entryClasses.get(i) == EntryType.TYPEINFO_PTR) {
                rttiIndices.add(i);
            }
        }

        // Parse each sub-vtable — we only care about the primary sub-vtable
        // per class (first occurrence)
        Set<String> seenPrimary = new HashSet<>();

        for (int r = 0; r < rttiIndices.size(); r++) {
            int rttiIdx = rttiIndices.get(r);
            long typeinfoAddr = entryValues.get(rttiIdx);
            String className = typeinfoToClassName.get(typeinfoAddr);
            if (className == null) continue;

            // Collect function pointer slots after the RTTI entry
            List<Long> slots = new ArrayList<>();
            Address addressPoint = null;

            int nextBoundary = (r + 1 < rttiIndices.size()) ?
                    rttiIndices.get(r + 1) : entryClasses.size();

            for (int i = rttiIdx + 1; i < nextBoundary; i++) {
                EntryType cls = entryClasses.get(i);
                if (cls == EntryType.FUNC_PTR) {
                    if (addressPoint == null) {
                        addressPoint = entryAddrs.get(i);
                    }
                    slots.add(entryValues.get(i));
                } else if (cls == EntryType.OFFSET) {
                    // Offset — could be pure_virtual which lands in code
                    // or we've hit the prefix of the next sub-vtable.
                    // Check if it's pure virtual
                    if (isPureVirtual(entryValues.get(i))) {
                        if (addressPoint == null) {
                            addressPoint = entryAddrs.get(i);
                        }
                        slots.add(entryValues.get(i));
                    } else {
                        break; // hit offset prefix of next sub-vtable
                    }
                } else {
                    break; // VTT or another typeinfo
                }
            }

            if (!slots.isEmpty() && addressPoint != null) {
                allVtableSlots.computeIfAbsent(className, k -> new ArrayList<>())
                        .add(slots);
                if (!seenPrimary.contains(className)) {
                    seenPrimary.add(className);
                    vtableSlots.put(className, slots);
                    vtableAddressPoints.put(className, addressPoint);
                }
            }
        }
    }

    private EntryType classifyEntry(long value) {
        if (typeinfoAddresses.contains(value)) return EntryType.TYPEINFO_PTR;
        if (value >= vtableRegionStart && value <= vtableRegionEnd) return EntryType.VTT_ENTRY;

        // Check executable — also check with thumb bit cleared
        if (isExecutable(value) || isExecutable(value & ~1L)) return EntryType.FUNC_PTR;

        return EntryType.OFFSET;
    }

    private boolean isExecutable(long value) {
        try {
            Address targetAddr = toAddr(value);
            MemoryBlock block = mem.getBlock(targetAddr);
            return (block != null && block.isExecute());
        } catch (Exception e) {
            return false;
        }
    }

    private void collectNamespaces() {
        SymbolIterator iter = symTable.getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            if (!sym.getName().equals("typeinfo")) continue;
            Namespace ns = sym.getParentNamespace();
            if (ns == null || ns.isGlobal()) continue;
            String className = ns.getName(true);
            classNamespaces.put(className, ns);
        }
    }

    private void processClass(String className) throws InvalidInputException {
        if (processed.contains(className)) return;
        processed.add(className);

        List<Long> mySlots = vtableSlots.get(className);
        if (mySlots == null) return;

        Namespace ns = classNamespaces.get(className);
        if (ns == null) {
            println("WARNING: No namespace found for " + className + ", skipping.");
            return;
        }

        // --- Primary sub-vtable (index 0) ---
        List<Long> parentSlots = null;
        List<String> parents = parentMap.get(className);
        if (parents != null && !parents.isEmpty()) {
            parentSlots = vtableSlots.get(parents.getFirst());
        }
        processSubVtable(className, ns, mySlots, parentSlots, true);

        // Label the primary vtable address point
        Address addressPoint = vtableAddressPoints.get(className);
        if (addressPoint != null) {
            try {
                symTable.createLabel(addressPoint, "vtable", ns,
                        SourceType.USER_DEFINED);
            } catch (Exception e) {
                println("WARNING: Could not label vtable for " + className);
            }
        }

        // --- Secondary sub-vtables ---
        List<List<Long>> allSubVtables = allVtableSlots.get(className);
        if (allSubVtables == null || allSubVtables.size() <= 1) return;
        // Build expected secondary base order.
        // If this class is __vmi (multiple parents), expand its own non-primary bases.
        // If this class is __si (one parent), inherit the parent's secondary sub-vtables.
        List<String> secondaryBaseOrder = new ArrayList<>();
        if (parents != null && parents.size() > 1) {
            // __vmi: expand non-primary bases
            for (int p = 1; p < parents.size(); p++) {
                expandBasesDepthFirst(parents.get(p), secondaryBaseOrder);
            }
        } else if (parents != null && parents.size() == 1) {
            // __si: inherit parent's secondary base order
            String parent = parents.getFirst();
            List<List<Long>> parentAllSubVtables = allVtableSlots.get(parent);
            if (parentAllSubVtables != null) {
                // Match secondary sub-vtables 1:1 against parent's secondaries
                for (int s = 1; s < parentAllSubVtables.size() && s < allSubVtables.size(); s++) {
                    processSubVtable(className, ns, allSubVtables.get(s),
                            parentAllSubVtables.get(s), false);
                }
                return;
            }
        }

        for (int s = 0; s < secondaryBaseOrder.size() && s + 1 < allSubVtables.size(); s++) {
            String baseClassName = secondaryBaseOrder.get(s);
            List<Long> secondarySlots = allSubVtables.get(s + 1);
            List<Long> baseSlots = vtableSlots.get(baseClassName);
            processSubVtable(className, ns, secondarySlots, baseSlots, false);
        }
    }

    private boolean isAncestorOf(String potentialAncestor, String className) {
        // Walk up className's parent chain looking for potentialAncestor
        Set<String> visited = new HashSet<>();
        List<String> toCheck = new ArrayList<>();
        toCheck.add(className);
        while (!toCheck.isEmpty()) {
            String current = toCheck.removeLast();
            if (visited.contains(current)) continue;
            visited.add(current);
            if (current.equals(potentialAncestor)) return true;
            List<String> parents = parentMap.get(current);
            if (parents != null) toCheck.addAll(parents);
        }
        return false;
    }

    private String findCommonAncestor(String classA, String classB) {
        // Collect all ancestors of classA
        Set<String> ancestorsA = new HashSet<>();
        List<String> toCheck = new ArrayList<>();
        toCheck.add(classA);
        while (!toCheck.isEmpty()) {
            String current = toCheck.removeLast();
            if (ancestorsA.contains(current)) continue;
            ancestorsA.add(current);
            List<String> parents = parentMap.get(current);
            if (parents != null) toCheck.addAll(parents);
        }

        // Walk up classB's ancestors, return first match
        // (BFS to find the closest common ancestor)
        java.util.ArrayDeque<String> bfsQueue = new java.util.ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        bfsQueue.add(classB);
        while (!bfsQueue.isEmpty()) {
            String current = bfsQueue.poll();
            if (visited.contains(current)) continue;
            visited.add(current);
            if (ancestorsA.contains(current)) return current;
            List<String> parents = parentMap.get(current);
            if (parents != null) bfsQueue.addAll(parents);
        }
        return null;
    }

    private void expandBasesDepthFirst(String baseClass, List<String> result) {
        result.add(baseClass);
        List<String> baseParents = parentMap.get(baseClass);
        if (baseParents != null && baseParents.size() > 1) {
            for (int i = 1; i < baseParents.size(); i++) {
                expandBasesDepthFirst(baseParents.get(i), result);
            }
        }
    }

    private void processSubVtable(String className, Namespace ns,
                                  List<Long> mySlots, List<Long> parentSlots,
                                  boolean isPrimary) throws InvalidInputException {
        // (same slot-by-slot logic as the old processClass body)
        int parentSlotCount = (parentSlots != null) ? parentSlots.size() : 0;
        for (int i = 0; i < mySlots.size(); i++) {
            long funcPtr = mySlots.get(i);
            if (isPureVirtual(funcPtr)) { pureVirtualCount++; continue; }
            if (i < parentSlotCount) {
                if (funcPtr == parentSlots.get(i)) { skipCount++; continue; }
            }
            Address funcAddr = toAddr(funcPtr & ~1L);

            if (getFunctionAt(funcAddr) == null) {
                try { disassemble(funcAddr); createFunction(funcAddr, null); }
                catch (Exception e) { println("WARNING: Could not create function at " + funcAddr); }
            }

            boolean alreadyNamed = false;
            Namespace existingNs = null;
            for (Symbol s : symTable.getSymbols(funcAddr)) {
                if (!s.getParentNamespace().isGlobal()) {
                    alreadyNamed = true;
                    existingNs = s.getParentNamespace();
                    break;
                }
            }
            if (alreadyNamed) {
                // Check if the existing name is from an ancestor
                String existingClassName = existingNs.getName(true);
                if (isAncestorOf(existingClassName, className)) {
                    skipCount++;
                    continue;
                }
                // Not an ancestor — find common ancestor and re-home
                String common = findCommonAncestor(existingClassName, className);
                if (common != null) {
                    Namespace commonNs = classNamespaces.get(common);
                    if (commonNs != null) {
                        // Remove old label, create under common ancestor
                        Symbol oldSym = null;
                        for (Symbol s : symTable.getSymbols(funcAddr)) {
                            if (s.getParentNamespace().equals(existingNs)) {
                                oldSym = s;
                                break;
                            }
                        }
                        if (oldSym != null) {
                            String oldName = oldSym.getName();
                            oldSym.delete();
                            symTable.createLabel(funcAddr, oldName, commonNs,
                                    SourceType.USER_DEFINED);
                            renameCount++; // count the re-home
                        }
                    }
                }
                skipCount++;
                continue;
            }

            String labelName;
            if (i == 0) labelName = isPrimary ? "D1" : String.format("D1_%s", funcAddr);
            else if (i == 1) labelName = isPrimary ? "D0" : String.format("D0_%s", funcAddr);
            else labelName = null;
            try {
                if (labelName != null) {
                    Symbol sym = getSymbolAt(funcAddr);
                    sym.setNamespace(ns);
                    sym.setName(labelName, SourceType.USER_DEFINED);
                } else {
                    labelName = String.format("FUN_%s", funcAddr);
                    symTable.createLabel(funcAddr, labelName, ns, SourceType.USER_DEFINED);
                }
                renameCount++;
            } catch (Exception e) {
                println("ERROR: Could not create label " + ns.getName(true) + "::" + labelName);
            }
        }
    }
}