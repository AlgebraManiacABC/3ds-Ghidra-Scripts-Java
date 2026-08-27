// Utility class for renaming vtable function entries using RTTI inheritance.
//
// Refactored from RenameVTableFunctions to accept pre-discovered vtable data
// from RTTIUtil rather than scanning a contiguous region.
//
// Usage (from a GhidraScript):
//   VTableRenamer renamer = new VTableRenamer(this);
//   renamer.run(vtableRttiSlots, typeinfoAddresses);
//
// @category RTTI
// @author Claude (for AlgebraManiacABC)

package util;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class RenameVTableFunctions {

    private static final int PTR_SIZE = 4;

    private final GhidraScript script;

    private SymbolTable symTab;
    private Memory mem;
    private Program program;

    // typeinfo address -> class name (fully qualified)
    private final Map<Long, String> typeinfoToClassName = new HashMap<>();
    // class name -> parent class names
    private final Map<String, List<String>> parentMap = new HashMap<>();
    // class name -> child class names
    private final Map<String, List<String>> childrenMap = new HashMap<>();
    // class name -> list of sub-vtable slot lists (index 0 = primary, 1+ = secondary)
    private final Map<String, List<List<Long>>> allVtableSlots = new HashMap<>();
    // class name -> primary vtable slot values
    private final Map<String, List<Long>> vtableSlots = new HashMap<>();
    // class name -> list of address points for each sub-vtable
    private final Map<String, List<Address>> allVtableAddressPoints = new HashMap<>();
    // class name -> primary vtable address point
    private final Map<String, Address> vtableAddressPoints = new HashMap<>();
    // class name -> Namespace
    private final Map<String, Namespace> classNamespaces = new HashMap<>();

    // Set of all known typeinfo addresses
    private final Set<Long> typeinfoAddresses = new HashSet<>();
    // __cxa_pure_virtual address (thumb bit masked)
    private long pureVirtualAddr = 0;
    private boolean externalPureVirtual = false;

    private final Set<String> processed = new HashSet<>();
    private final Map<String, Program> importedPrograms = new HashMap<>();

    private int renameCount = 0;
    private int skipCount = 0;
    private int pureVirtualCount = 0;

    public RenameVTableFunctions(GhidraScript script) {
        this.script = script;
    }

    // ---------------------------------------------------------------
    //  Public API
    // ---------------------------------------------------------------

    /**
     * Run the vtable rename pipeline.
     *
     * @param vtableRttiSlots  Map of vtable RTTI slot address -> typeinfo address
     * @param knownTypeinfos   Set of all known typeinfo struct addresses
     */
    public void run(Program prog, Map<Long, Long> vtableRttiSlots, Set<Long> knownTypeinfos,
                    TaskMonitor monitor, GhidraState state)
            throws Exception {
        // Clear state from any previous run
        typeinfoToClassName.clear();
        parentMap.clear();
        childrenMap.clear();
        allVtableSlots.clear();
        vtableSlots.clear();
        allVtableAddressPoints.clear();
        vtableAddressPoints.clear();
        classNamespaces.clear();
        typeinfoAddresses.clear();
        processed.clear();
        importedPrograms.clear();
        pureVirtualAddr = 0;
        externalPureVirtual = false;
        renameCount = 0;
        skipCount = 0;
        pureVirtualCount = 0;

        program = prog;
        symTab = prog.getSymbolTable();
        mem = prog.getMemory();
        typeinfoAddresses.addAll(knownTypeinfos);

        script.printf("=== RTTI Renaming Pipeline for %s ===\n",program.getName());

        // Step 1: Find __cxa_pure_virtual
        findPureVirtual();

        // Step 2: Build inheritance tree from typeinfo symbols
        buildInheritanceTree();
        script.printf("    Classes found: %d ", typeinfoToClassName.size());

        // Step 3: Parse vtable slots from discovered RTTI slot locations
        parseVtableSlots(vtableRttiSlots);
        script.printf("(%d with vtable data)\n", vtableSlots.size());

        // Step 3.5: If __cxa_pure_virtual wasn't found by symbol, detect by vtable analysis
        if (pureVirtualAddr == 0 && !externalPureVirtual) {
            detectPureVirtual();
        }
        if (pureVirtualAddr == 0 && !externalPureVirtual) {
            script.printf("    WARNING: No __cxa_pure_virtual for %s\n",program.getName());
        }

        // Step 4: Collect namespace objects
        collectNamespaces();

        // Step 5: Process in topological order (Kahn's algorithm)

        Map<String, Integer> inDegree = new HashMap<>();
        for (String className : typeinfoToClassName.values()) {
            inDegree.put(className, 0);
        }
        for (Map.Entry<String, List<String>> entry : parentMap.entrySet()) {
            inDegree.put(entry.getKey(), entry.getValue().size());
        }

        ArrayDeque<String> queue = new ArrayDeque<>();
        for (Map.Entry<String, Integer> entry : inDegree.entrySet()) {
            if (entry.getValue() == 0) {
                queue.add(entry.getKey());
            }
        }

        while (!queue.isEmpty()) {
            String className = queue.poll();
            processClass(className);

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

        // Step 6: Propagate discovered names upward through the hierarchy
        propagateNames();

        if (script.askYesNo("Auto Fill in Classes?",
                "Run Auto Fill in Class for all discovered classes? This can take a long time!")) {
            AutoFillClasses.fill(prog, monitor, state);
        }

        // Report unreached classes
        int unreached = 0;
        for (String className : vtableSlots.keySet()) {
            if (!processed.contains(className)) {
                unreached++;
                if (unreached <= 20) {
                    script.println("    UNREACHED: " + className +
                            " (parent: " + parentMap.getOrDefault(className, List.of()) + ")");
                }
            }
        }
        if (unreached > 20) {
            script.println("... and " + (unreached - 20) + " more unreached classes.");
        }

        // Release CRO programs
        for (Program p : importedPrograms.values()) {
            if (p != null && p != program) {
                p.release(script);
            }
        }
    }

    // ---------------------------------------------------------------
    //  Pure virtual detection
    // ---------------------------------------------------------------

    private void findPureVirtual() {
        SymbolIterator iter = program.getSymbolTable().getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            if (sym.getName().contains("__cxa_pure_virtual")) {
                pureVirtualAddr = sym.getAddress().getOffset();
                script.println("Found __cxa_pure_virtual at 0x" +
                        Long.toHexString(pureVirtualAddr));
                return;
            }
        }

        ReferenceManager refMan = program.getReferenceManager();
        ReferenceIterator refIter = refMan.getExternalReferences();
        while (refIter.hasNext()) {
            if (refIter.next() instanceof ExternalReference extRef) {
                if (extRef.getLabel().contains("__cxa_pure_virtual")) {
                    pureVirtualAddr = extRef.getExternalLocation()
                            .getAddress().getOffset();
                    externalPureVirtual = true;
                    script.println("Found __cxa_pure_virtual at 0x" +
                            Long.toHexString(pureVirtualAddr) +
                            " within " + extRef.getLibraryName());
                    return;
                }
            }
        }
    }

    private boolean isPureVirtualRef(Address addr) throws MemoryAccessException {
        if (pureVirtualAddr == 0) return false;
        if (externalPureVirtual) {
            ReferenceManager refMan = program.getReferenceManager();
            Reference[] refs = refMan.getReferencesFrom(addr);
            for (Reference ref : refs) {
                if (ref instanceof ExternalReference extRef) {
                    if (extRef.getLabel().contains("cxa_pure_virtual"))
                        return true;
                    if (extRef.getExternalLocation().getAddress().equals(addr))
                        return true;
                }
            }
            return false;
        }
        long funcPtr = Integer.toUnsignedLong(program.getMemory().getInt(addr));
        return (funcPtr & ~1L) == (pureVirtualAddr & ~1L);
    }

    // ---------------------------------------------------------------
    //  Inheritance tree
    // ---------------------------------------------------------------

    private void buildInheritanceTree() throws Exception {
        collectTypeinfoSymbols(program);

        for (Map.Entry<Long, String> entry :
                new ArrayList<>(typeinfoToClassName.entrySet())) {
            resolveParents(program, entry.getKey(), entry.getValue());
        }

        for (Program prog : importedPrograms.values()) {
            if (prog != null && prog != program) {
                prog.release(script);
            }
        }
        importedPrograms.clear();
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

            // Skip __cxxabiv1 infrastructure classes
            if (className.startsWith("__cxxabiv1")) continue;

            if (ns instanceof Library) {
                if (!sym.hasReferences()) continue;
            }

            if (!typeinfoToClassName.containsKey(addr)) {
                typeinfoToClassName.put(addr, className);
                typeinfoAddresses.add(addr);
            }
        }
    }

    private void resolveParents(Program program, long tiAddr, String className)
            throws Exception {
        if (parentMap.containsKey(className)) return;

        Memory progMem = program.getMemory();
        Listing progListing = program.getListing();
        Address addr = program.getAddressFactory()
                .getDefaultAddressSpace().getAddress(tiAddr);

        String rttiType = null;
        Data data = progListing.getDataAt(addr);
        if (data != null) {
            int size = data.getLength();
            if (size == 8) rttiType = "__class_type_info";
            else if (size == 12) rttiType = "__si_class_type_info";
            else if (size >= 16) rttiType = "__vmi_class_type_info";
        }
        if (rttiType == null) {
            if (className.contains("vmi_class")) rttiType = "__vmi_class_type_info";
            else if (className.contains("si_class")) rttiType = "__si_class_type_info";
            else if (className.contains("class_type")) rttiType = "__class_type_info";
        }
        if (rttiType == null) {
            script.println("    WARNING: Could not determine RTTI type for " +
                    className + " at " + addr + " in " + program.getName());
            return;
        }

        switch (rttiType) {
            case "__class_type_info" -> {}
            case "__si_class_type_info" -> resolveBaseType(program, addr.add(8), className);
            case "__vmi_class_type_info" -> {
                int baseCount = progMem.getInt(addr.add(12));
                for (int b = 0; b < baseCount; b++) {
                    resolveBaseType(program, addr.add(16 + b * 8L), className);
                }
            }
        }
    }

    private void resolveBaseType(Program program,
                                 Address baseFieldAddr,
                                 String childClassName) throws Exception {
        Memory progMem = program.getMemory();
        long basePtr = Integer.toUnsignedLong(progMem.getInt(baseFieldAddr));

        String parentName = typeinfoToClassName.get(basePtr);
        if (parentName != null) {
            addParentChild(childClassName, parentName);
            return;
        }

        if (basePtr == 0 || isOnUnresolved(basePtr)) {
            ExternalTypeinfoResult result =
                    resolveExternalTypeinfo(program, baseFieldAddr);
            if (result != null) {
                if (!typeinfoToClassName.containsKey(result.typeinfoAddr)) {
                    typeinfoToClassName.put(result.typeinfoAddr, result.className);
                    typeinfoAddresses.add(result.typeinfoAddr);
                }
                addParentChild(childClassName, result.className);
                resolveParents(result.program, result.typeinfoAddr, result.className);
            } else {
                script.println("    WARNING: Could not resolve external parent for " +
                        childClassName + " at " + baseFieldAddr);
            }
            return;
        }

        script.println("    WARNING: Unknown base typeinfo pointer 0x" +
                Long.toHexString(basePtr) + " for " + childClassName);
    }

    private boolean isOnUnresolved(long addr) {
        Address realAddr = program.getMinAddress().getAddressSpace().getAddress(addr);
        Symbol[] syms = symTab.getSymbols(realAddr);
        if (syms != null && syms.length > 0) {
            return syms[0].getName().equals("OnUnresolved");
        }
        return false;
    }

    private void addParentChild(String childName, String parentName) {
        parentMap.computeIfAbsent(childName, k -> new ArrayList<>()).add(parentName);
        childrenMap.computeIfAbsent(parentName, k -> new ArrayList<>()).add(childName);
    }

    // ---------------------------------------------------------------
    //  Cross-module resolution
    // ---------------------------------------------------------------

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
            ProjectData projectData = script.getState().getProject().getProjectData();
            DomainFile domainFile = projectData.getFile(progPath);
            if (domainFile == null) {
                script.println("    WARNING: Could not find CRO program: " + progPath);
                importedPrograms.put(progPath, null);
                return null;
            }
            Program prog = (Program) domainFile.getDomainObject(
                    script, true, false, script.getMonitor());
            importedPrograms.put(progPath, prog);
            collectTypeinfoSymbols(prog);
            return prog;
        } catch (Exception e) {
            script.println("    ERROR: Could not open CRO program " +
                    progPath + ": " + e.getMessage());
            importedPrograms.put(progPath, null);
            return null;
        }
    }

    private ExternalTypeinfoResult resolveExternalTypeinfo(
            Program sourceProgram, Address refAddr) {
        ReferenceManager refMgr = sourceProgram.getReferenceManager();
        Reference[] refs = refMgr.getReferencesFrom(refAddr);

        for (Reference ref : refs) {
            if (!(ref instanceof ExternalReference extRef)) continue;
            ExternalLocation extLoc = extRef.getExternalLocation();

            ExternalManager exMan = sourceProgram.getExternalManager();
            Library imported = exMan.getExternalLibrary(extLoc.getLibraryName());
            if (imported == null) continue;
            String progPath = imported.getAssociatedProgramPath();
            if (progPath == null) continue;

            Program croProg = openCroProgram(progPath);
            if (croProg == null) continue;

            Address extAddr = extLoc.getAddress();
            if (extAddr == null) continue;

            Address croAddr = croProg.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(extAddr.getOffset());

            Symbol[] syms = croProg.getSymbolTable().getSymbols(croAddr);
            for (Symbol sym : syms) {
                if (sym.getName().equals("typeinfo")) {
                    Namespace ns = sym.getParentNamespace();
                    if (ns != null && !ns.isGlobal()) {
                        ExternalTypeinfoResult result = new ExternalTypeinfoResult();
                        result.program = croProg;
                        result.typeinfoAddr = croAddr.getOffset();
                        result.className = ns.getName(true);
                        return result;
                    }
                }
            }

            // Fallback: read name pointer
            try {
                Memory croMem = croProg.getMemory();
                long namePtr = Integer.toUnsignedLong(croMem.getInt(croAddr.add(4)));
                Address namePtrAddr = croProg.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(namePtr);
                Symbol[] nameSyms = croProg.getSymbolTable().getSymbols(namePtrAddr);
                for (Symbol sym : nameSyms) {
                    Namespace ns = sym.getParentNamespace();
                    if (ns != null && !ns.isGlobal()) {
                        ExternalTypeinfoResult result = new ExternalTypeinfoResult();
                        result.program = croProg;
                        result.typeinfoAddr = croAddr.getOffset();
                        result.className = ns.getName(true);
                        return result;
                    }
                }
            } catch (Exception e) {
                script.println("WARNING: Could not read CRO typeinfo at " +
                        croAddr + " in " + progPath);
            }
        }
        return null;
    }

    // ---------------------------------------------------------------
    //  Name propagation: push child-discovered names up to ancestors
    // ---------------------------------------------------------------

    /**
     * After the initial rename pass, some slots only have names in child classes.
     * For each sub-vtable index, if a descendant has a non-generic name at slot N,
     * propagate that name to every ancestor that also has slot N in the same
     * sub-vtable — renaming generic (FUN_*) functions to match.
     */
    private int propagateNames() throws Exception {
        int count = 0;

        AddressSpace addressSpace = program.getMinAddress().getAddressSpace();
        // For each class that has vtable data, check each sub-vtable
        for (String className : processed) {
            List<List<Long>> subVtables = allVtableSlots.get(className);
            List<Address> addressPoints = allVtableAddressPoints.get(className);
            if (subVtables == null || addressPoints == null) continue;

            for (int sub = 0; sub < subVtables.size(); sub++) {
                List<Long> slots = subVtables.get(sub);
                Address base = (sub < addressPoints.size()) ? addressPoints.get(sub) : null;
                if (base == null) continue;

                for (int i = 0; i < slots.size(); i++) {
                    long funcPtr = slots.get(i);
                    if (funcPtr == 0) continue;
                    Address funcAddr = addressSpace.getAddress(funcPtr & ~1L);

                    // Get the current name at this function
                    String name = getNonGenericName(funcAddr);
                    if (name == null) continue;

                    // Walk up through ancestors and propagate
                    count += propagateToAncestors(className, sub, i, name);
                }
            }
        }

        return count;
    }

    /**
     * Returns the function name if it is non-generic (not FUN_*, not D0/D1),
     * or null if generic/absent.
     */
    private String getNonGenericName(Address funcAddr) {
        for (Symbol s : symTab.getSymbols(funcAddr)) {
            String name = s.getName();
            if (name.startsWith("FUN_") || name.startsWith("thunk_")) continue;
            if (name.equals("D0") || name.equals("D1")) continue;
            if (name.startsWith("D0_") || name.startsWith("D1_")) continue;
            if (!s.getParentNamespace().isGlobal()) {
                return name;
            }
        }
        return null;
    }

    /**
     * Propagate a name upward from a child class to all ancestors that have
     * the same sub-vtable index.
     */
    private int propagateToAncestors(String childClass, int subVtableIdx,
                                     int slotIdx, String name) throws Exception {
        int count = 0;
        List<String> parents = parentMap.get(childClass);
        if (parents == null) return 0;

        for (String parent : parents) {
            count += propagateToAncestor(parent, subVtableIdx, slotIdx, name, new HashSet<>());
        }
        return count;
    }

    private int propagateToAncestor(String ancestor, int subVtableIdx,
                                    int slotIdx, String name,
                                    Set<String> visited) throws Exception {
        if (!visited.add(ancestor)) return 0;
        int count = 0;

        AddressSpace addressSpace = program.getMinAddress().getAddressSpace();
        // Check if this ancestor has the slot in the same sub-vtable
        List<List<Long>> subVtables = allVtableSlots.get(ancestor);
        List<Address> addressPoints = allVtableAddressPoints.get(ancestor);
        if (subVtables != null && addressPoints != null &&
                subVtableIdx < subVtables.size() && subVtableIdx < addressPoints.size()) {

            List<Long> ancestorSlots = subVtables.get(subVtableIdx);
            Address ancestorBase = addressPoints.get(subVtableIdx);

            if (slotIdx < ancestorSlots.size() && ancestorBase != null) {
                long funcPtr = ancestorSlots.get(slotIdx);
                if (funcPtr != 0) {
                    Address funcAddr = addressSpace.getAddress(funcPtr & ~1L);

                    // Only rename if the current name is generic
                    String currentName = getNonGenericName(funcAddr);
                    if (currentName == null) {
                        // This slot has a generic name — apply the discovered name
                        // For destructors, use the ancestor's own class name
                        String appliedName = name;
                        if (name.startsWith("~")) {
                            String leafName = ancestor;
                            int lastSep = ancestor.lastIndexOf("::");
                            if (lastSep >= 0) {
                                leafName = ancestor.substring(lastSep + 2);
                            }
                            appliedName = "~" + leafName;
                        }

                        SymbolTable symTab = program.getSymbolTable();
                        Symbol[] syms = symTab.getSymbols(funcAddr);
                        if (syms != null && syms.length > 0) {
                            Symbol sym = syms[0];
                            if (sym != null && (sym.getName().startsWith("FUN_") ||
                                    sym.getName().startsWith("thunk_"))) {
                                sym.setName(appliedName, SourceType.USER_DEFINED);
                                count++;
                            }
                        }
                    }
                }
            }
        }

        // Continue upward
        List<String> grandparents = parentMap.get(ancestor);
        if (grandparents != null) {
            for (String gp : grandparents) {
                count += propagateToAncestor(gp, subVtableIdx, slotIdx, name, visited);
            }
        }

        return count;
    }

    // ---------------------------------------------------------------
    //  Vtable slot parsing (from pre-discovered RTTI slot locations)
    // ---------------------------------------------------------------

    private void parseVtableSlots(Map<Long, Long> vtableRttiSlots) throws Exception {
        // Sort RTTI slots by address for sequential processing
        List<Long> sortedSlotAddrs = new ArrayList<>(vtableRttiSlots.keySet());
        Collections.sort(sortedSlotAddrs);

        Set<String> seenPrimary = new HashSet<>();

        AddressSpace addressSpace = program.getMinAddress().getAddressSpace();
        Listing listing = program.getListing();
        for (int r = 0; r < sortedSlotAddrs.size(); r++) {
            long rttiSlotAddr = sortedSlotAddrs.get(r);
            long typeinfoAddr = vtableRttiSlots.get(rttiSlotAddr);
            String className = typeinfoToClassName.get(typeinfoAddr);
            if (className == null) continue;

            Address slotAddress = addressSpace.getAddress(rttiSlotAddr);

            // Apply pointer data type at the RTTI slot
            try {
                Reference[] refs = program.getReferenceManager().getReferencesFrom(slotAddress);
                Reference extRef = null;
                for (Reference ref : refs) {
                    if (ref.isExternalReference()) {
                        extRef = ref;
                        break;
                    }
                }
                listing.clearCodeUnits(slotAddress, slotAddress, true);
                listing.createData(slotAddress, PointerDataType.dataType);
                if (extRef != null) {
                    program.getReferenceManager().addReference(extRef);
                }
            } catch (Exception e) { /* already applied */ }

            // Walk forward from the slot after the RTTI pointer to collect function pointers
            List<Long> slots = new ArrayList<>();
            Address addressPoint = null;

            // The next boundary is the next RTTI slot (or end of rodata)
            long nextBoundary;
            if (r + 1 < sortedSlotAddrs.size()) {
                nextBoundary = sortedSlotAddrs.get(r + 1);
            } else {
                MemoryBlock rodata = findRodataBlock(program);
                nextBoundary = (rodata != null) ?
                        rodata.getEnd().getOffset() + 1 : rttiSlotAddr + 0x10000;
            }

            long current = rttiSlotAddr + PTR_SIZE;
            while (current < nextBoundary) {
                Address currentAddr = addressSpace.getAddress(current);
                long value = Integer.toUnsignedLong(program.getMemory().getInt(currentAddr));

                if (!isFunctionPointer(currentAddr, value)) break;

                if (addressPoint == null) {
                    addressPoint = currentAddr;
                }
                slots.add(value);

                // Apply pointer data type
                try {
                    Reference[] refs = program.getReferenceManager().getReferencesFrom(currentAddr);
                    Reference extRef = null;
                    for (Reference ref : refs) {
                        if (ref.isExternalReference()) {
                            extRef = ref;
                            break;
                        }
                    }
                    listing.clearCodeUnits(currentAddr, currentAddr, true);
                    listing.createData(currentAddr, PointerDataType.dataType);
                    if (extRef != null) {
                        program.getReferenceManager().addReference(extRef);
                    }
                } catch (Exception e) { /* already applied */ }

                current += PTR_SIZE;
            }

            if (!slots.isEmpty() && addressPoint != null) {
                allVtableSlots.computeIfAbsent(className, k -> new ArrayList<>())
                        .add(slots);
                allVtableAddressPoints.computeIfAbsent(className, k -> new ArrayList<>())
                        .add(addressPoint);
                if (!seenPrimary.contains(className)) {
                    seenPrimary.add(className);
                    vtableSlots.put(className, slots);
                    vtableAddressPoints.put(className, addressPoint);
                }
            }
        }
    }

    /**
     * Detect __cxa_pure_virtual by finding a function pointer that appears
     * in vtable slots of two classes that share no inheritance relationship.
     */
    private void detectPureVirtual() throws Exception {
        // Pass 1: group non-zero slot values by class
        Map<Long, Set<String>> valuesToClasses = new HashMap<>();
        for (Map.Entry<String, List<List<Long>>> entry : allVtableSlots.entrySet()) {
            String className = entry.getKey();
            for (List<Long> subVtable : entry.getValue()) {
                for (long val : subVtable) {
                    if (val == 0) continue;
                    valuesToClasses.computeIfAbsent(val, k -> new HashSet<>())
                            .add(className);
                }
            }
        }

        List<Long> candidates = new ArrayList<>();
        for (Map.Entry<Long, Set<String>> entry : valuesToClasses.entrySet()) {
            if (entry.getValue().size() < 2) continue;
            if ((entry.getKey() & 1L) == 0) continue;
            if (hasUnrelatedPair(entry.getValue())) {
                candidates.add(entry.getKey());
            }
        }

        if (!candidates.isEmpty()) {
            candidates.sort(Comparator.comparingInt(k -> valuesToClasses.get(k).size()).reversed());
            pureVirtualAddr = candidates.getFirst() & ~1L;
            script.println("    Detected __cxa_pure_virtual at 0x" +
                    Long.toHexString(pureVirtualAddr) +
                    " (thumb function which appears in unrelated vtables)");
            AddressSpace addrSpace = program.getMinAddress().getAddressSpace();
            CreateFunctionCmd cmd = new CreateFunctionCmd("__cxa_pure_virtual",
                    addrSpace.getAddress(pureVirtualAddr),null,SourceType.USER_DEFINED);
            cmd.applyTo(program);
            if (candidates.size() > 1) {
                script.println("    WARNING: " + candidates.size() +
                        " candidates found for __cxa_pure_virtual:");
                for (long addr : candidates) {
                    script.println("  0x" + Long.toHexString(addr) +
                            " (" + valuesToClasses.get(addr).size() + " classes)");
                }
            }
            return;
        }

        // Pass 2: group zero-valued slots (external refs) by target
        Map<ExternalLocation, Set<String>> extKeyToClasses = new HashMap<>();
        ReferenceManager refMgr = program.getReferenceManager();
        for (Map.Entry<String, List<List<Long>>> entry : allVtableSlots.entrySet()) {
            String className = entry.getKey();
            List<List<Long>> subVtables = entry.getValue();
            List<Address> addrPoints = allVtableAddressPoints.get(className);
            if (addrPoints == null) continue;

            for (int s = 0; s < subVtables.size(); s++) {
                if (s >= addrPoints.size() || addrPoints.get(s) == null) continue;
                Address base = addrPoints.get(s);
                List<Long> slots = subVtables.get(s);
                for (int i = 0; i < slots.size(); i++) {
                    if (slots.get(i) != 0) continue;
                    Address slotAddr = base.add(4L * i);
                    for (Reference ref : refMgr.getReferencesFrom(slotAddr)) {
                        if (ref instanceof ExternalReference extRef) {
                            ExternalLocation loc = extRef.getExternalLocation();
                            extKeyToClasses.computeIfAbsent(loc, k -> new HashSet<>())
                                    .add(className);
                        }
                    }
                }
            }
        }

        Set<ExternalLocation> extCandidates = new HashSet<>();
        ProgramManager pman = script.getState().getTool().getService(ProgramManager.class);
        for (Map.Entry<ExternalLocation, Set<String>> entry : extKeyToClasses.entrySet()) {
            Address extAddr = entry.getKey().getAddress();
            String libName = entry.getKey().getLibraryName();
            String libPath = program.getExternalManager().getExternalLibraryPath(libName);
            Program extProg = pman.openCachedProgram(script.parseDomainFile(libPath), this);
            Symbol[] syms = extProg.getSymbolTable().getSymbols(extAddr);
            boolean located = false;
            for (var sym : syms) {
                if (sym.getName().contains("cxa_pure_virtual")) {
                    extCandidates.add(entry.getKey());
                    entry.getKey().getSymbol().setName("__cxa_pure_virtual", SourceType.USER_DEFINED);
                    located = true;
                }
            }
            if (!located && (extAddr.getOffset() & 1L) == 1) {
                syms = extProg.getSymbolTable().getSymbols(extAddr.subtract(1));
                for (var sym : syms) {
                    if (sym.getName().contains("cxa_pure_virtual")) {
                        extCandidates.add(entry.getKey());
                        entry.getKey().getSymbol().setName("__cxa_pure_virtual", SourceType.USER_DEFINED);
                    }
                }
            }
            extProg.release(this);
        }

        if (extCandidates.isEmpty()) {
            return;
        }

        ExternalLocation loc = extCandidates.stream().findFirst().get();
        externalPureVirtual = true;
        pureVirtualAddr = loc.getAddress() != null ? loc.getAddress().getOffset() : 0;
        script.println("    Detected external __cxa_pure_virtual: " + loc +
                " in " + loc.getLibraryName());

        if (extCandidates.size() > 1) {
            script.println("    WARNING: " + extCandidates.size() +
                    " external candidates found for __cxa_pure_virtual:");
            extCandidates.stream().sorted(Comparator.comparingInt(
                    key -> extKeyToClasses.get(key).size()))
                    .forEach(key -> script.println("  " + key +
                    " (" + extKeyToClasses.get(key).size() + " classes)"));
        }
    }

    private boolean hasUnrelatedPair(Set<String> classes) {
        List<String> list = new ArrayList<>(classes);
        for (int i = 0; i < list.size() - 1; i++) {
            for (int j = i + 1; j < list.size(); j++) {
                if (findCommonAncestor(list.get(i), list.get(j)) == null) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Check if a value at an address is a function pointer:
     * points into .text or has an external reference to a function.
     */
    private boolean isFunctionPointer(Address addr, long value) {
        // Check external reference first
        ReferenceManager refMgr = program.getReferenceManager();
        for (Reference ref : refMgr.getReferencesFrom(addr)) {
            if (ref instanceof ExternalReference) {
                return true;
            }
        }

        // Check if value points to executable memory (with thumb bit cleared)
        return isExecutable(value) || isExecutable(value & ~1L);
    }

    private boolean isExecutable(long value) {
        try {
            AddressSpace addressSpace = program.getMinAddress().getAddressSpace();
            Address targetAddr = addressSpace.getAddress(value);
            MemoryBlock block = mem.getBlock(targetAddr);
            return (block != null && block.isExecute());
        } catch (Exception e) {
            return false;
        }
    }

    private MemoryBlock findRodataBlock(Program program) {
        Memory m = program.getMemory();
        for (MemoryBlock block : m.getBlocks()) {
            String name = block.getName();
            if (name.equals(".rodata") || name.equals("rodata")) {
                return block;
            }
        }
        for (MemoryBlock block : m.getBlocks()) {
            if (block.isRead() && !block.isWrite() && !block.isExecute()) {
                return block;
            }
        }
        return null;
    }

    // ---------------------------------------------------------------
    //  Namespace collection
    // ---------------------------------------------------------------

    private void collectNamespaces() {
        SymbolIterator iter = symTab.getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            if (!sym.getName().equals("typeinfo")) continue;
            Namespace ns = sym.getParentNamespace();
            if (ns == null || ns.isGlobal()) continue;
            String className = ns.getName(true);
            if (!(ns instanceof GhidraClass)) {
                try {
                    ns = NamespaceUtils.convertNamespaceToClass(ns);
                } catch (Exception e) {
                    script.println("WARNING: Could not convert " + className + " to class");
                }
            }
            classNamespaces.put(className, ns);
        }
    }

    // ---------------------------------------------------------------
    //  Class processing (rename logic)
    // ---------------------------------------------------------------

    private void processClass(String className) throws Exception {
        if (processed.contains(className)) return;
        processed.add(className);

        List<Long> mySlots = vtableSlots.get(className);
        if (mySlots == null) return;

        Namespace ns = classNamespaces.get(className);
        if (ns == null) {
            script.println("WARNING: No namespace found for " + className + ", skipping.");
            return;
        }

        // Label primary vtable address point
        Address addressPoint = vtableAddressPoints.get(className);
        if (addressPoint != null) {
            try {
                symTab.createLabel(addressPoint, "vtable", ns, SourceType.USER_DEFINED);
            } catch (Exception e) {
                script.println("WARNING: Could not label vtable for " + className);
            }
        }

        // Primary sub-vtable
        List<Long> parentSlots = null;
        List<String> parents = parentMap.get(className);
        if (parents != null && !parents.isEmpty()) {
            parentSlots = vtableSlots.get(parents.getFirst());
        }
        processSubVtable(className, ns, addressPoint, mySlots, parentSlots, true);

        // Secondary sub-vtables
        List<List<Long>> allSubVtables = allVtableSlots.get(className);
        if (allSubVtables == null || allSubVtables.size() <= 1) return;

        List<String> secondaryBaseOrder = new ArrayList<>();
        if (parents != null && parents.size() > 1) {
            for (int p = 1; p < parents.size(); p++) {
                expandBasesDepthFirst(parents.get(p), secondaryBaseOrder);
            }
        } else if (parents != null && parents.size() == 1) {
            String parent = parents.getFirst();
            List<List<Long>> parentAllSubVtables = allVtableSlots.get(parent);
            if (parentAllSubVtables != null) {
                List<Address> myAddressPoints = allVtableAddressPoints.get(className);
                for (int s = 1; s < parentAllSubVtables.size() && s < allSubVtables.size(); s++) {
                    Address secAddr = (myAddressPoints != null && s < myAddressPoints.size())
                            ? myAddressPoints.get(s) : null;
                    processSubVtable(className, ns, secAddr, allSubVtables.get(s),
                            parentAllSubVtables.get(s), false);
                }
                return;
            }
            List<Address> myAddressPoints = allVtableAddressPoints.get(className);
            for (int s = 1; s < allSubVtables.size(); s++) {
                Address secAddr = (myAddressPoints != null && s < myAddressPoints.size())
                        ? myAddressPoints.get(s) : null;
                processSubVtable(className, ns, secAddr, allSubVtables.get(s), null, false);
            }
            return;
        }

        List<Address> myAddressPoints = allVtableAddressPoints.get(className);
        for (int s = 0; s < secondaryBaseOrder.size() && s + 1 < allSubVtables.size(); s++) {
            String baseClassName = secondaryBaseOrder.get(s);
            List<Long> secondarySlots = allSubVtables.get(s + 1);
            List<Long> baseSlots = vtableSlots.get(baseClassName);
            Address secAddr = (myAddressPoints != null && s + 1 < myAddressPoints.size())
                    ? myAddressPoints.get(s + 1) : null;
            processSubVtable(className, ns, secAddr, secondarySlots, baseSlots, false);
        }
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

    private boolean isAncestorOf(String potentialAncestor, String className) {
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

        ArrayDeque<String> bfsQueue = new ArrayDeque<>();
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

    private boolean callsOperatorDelete(Address funcAddr) {
        try {
            Function func = program.getListing().getFunctionAt(funcAddr);
            if (func == null) return false;

            InstructionIterator iter =
                    program.getListing().getInstructions(func.getBody(), true);
            while (iter.hasNext()) {
                Instruction inst = iter.next();
                FlowType flow = inst.getFlowType();
                if (flow.isCall() || flow.isJump()) {
                    for (Address target : inst.getFlows()) {
                        Symbol[] syms = symTab.getSymbols(target);
                        if (syms != null) {
                            for (Symbol sym : syms) {
                                if (sym.getName().equals("operator.delete")) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // fall through
        }
        return false;
    }

    private Namespace createNamespace(Program program, Namespace parent, String name) throws Exception {
        return program.getSymbolTable()
                .createNameSpace(parent, name, SourceType.USER_DEFINED);
    }

    private void processSubVtable(String className, Namespace ns, Address start,
                                  List<Long> mySlots, List<Long> parentSlots,
                                  boolean isPrimary) throws Exception {
        int parentSlotCount = (parentSlots != null) ? parentSlots.size() : 0;
        AddressSpace addressSpace = program.getMinAddress().getAddressSpace();
        for (int i = 0; i < mySlots.size(); i++) {
            long funcPtr = mySlots.get(i);
            Address slotAddr = start.add(4L * i);
            if (isPureVirtualRef(slotAddr)) { pureVirtualCount++; continue; }
            if (funcPtr == 0) { skipCount++; continue; }
            boolean isExternal = false;
            for (Reference r : program.getReferenceManager().getReferencesFrom(slotAddr)) {
                if (r instanceof ExternalReference) { isExternal = true; break; }
            }
            if (isExternal) { skipCount++; continue; }
            if (i < parentSlotCount) {
                if (funcPtr == parentSlots.get(i)) { skipCount++; continue; }
            }
            Address funcAddr = addressSpace.getAddress(funcPtr & ~1L);

            Function func = program.getListing().getFunctionAt(funcAddr);
            if (func == null) {
                try {
                    DisassembleCommand dCmd = new DisassembleCommand(funcAddr,null,true);
                    dCmd.applyTo(program);
                    CreateFunctionCmd fCmd = new CreateFunctionCmd(funcAddr);
                    fCmd.applyTo(program);
                    func = program.getListing().getFunctionAt(funcAddr);
                } catch (Exception e) {
                    script.println("WARNING: Could not create function at " + funcAddr);
                }
            }

            // Set calling convention to __thiscall
            if (func != null) {
                try {
                    if (!"__thiscall".equals(func.getCallingConventionName())) {
                        func.updateFunction("__thiscall",
                                null, List.of(),
                                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                                true, SourceType.USER_DEFINED);
                    }
                } catch (Exception e) { /* may already be set */ }
            }

            boolean alreadyNamed = false;
            Namespace existingNs = null;
            for (Symbol s : symTab.getSymbols(funcAddr)) {
                if (!s.getParentNamespace().isGlobal()) {
                    alreadyNamed = true;
                    existingNs = s.getParentNamespace();
                    break;
                }
            }
            if (alreadyNamed) {
                String existingClassName = existingNs.getName(true);
                if (isAncestorOf(existingClassName, className)) {
                    skipCount++;
                    continue;
                }
                String common = findCommonAncestor(existingClassName, className);
                if (common != null) {
                    Namespace commonNs = classNamespaces.get(common);
                    if (commonNs == null && NamespaceUtils.getNamespacesByName(
                            program, program.getGlobalNamespace(), common)
                            .isEmpty()) {
                        try {
                            commonNs = createNamespace(program,
                                    program.getGlobalNamespace(), common);
                            classNamespaces.put(common, commonNs);
                        } catch (Exception e) {
                            script.println("    FAILED: could not create namespace " + common);
                        }
                    }
                    if (commonNs != null) {
                        Symbol oldSym = null;
                        for (Symbol s : symTab.getSymbols(funcAddr)) {
                            if (s.getParentNamespace().equals(existingNs)) {
                                oldSym = s;
                                break;
                            }
                        }
                        if (oldSym != null) {
                            String oldName = oldSym.getName();
                            oldSym.delete();
                            symTab.createLabel(funcAddr, oldName, commonNs,
                                    SourceType.USER_DEFINED);
                            renameCount++;
                        }
                    }
                }
                skipCount++;
                continue;
            }

            boolean D0 = (callsOperatorDelete(funcAddr));
            String name = D0 && isPrimary ? "D0"
                    : D0 ? String.format("D0_%s", funcAddr)
                    : null;
            try {
                SymbolTable symTab = program.getSymbolTable();
                Symbol[] syms = symTab.getSymbols(funcAddr);
                if (syms != null && syms.length > 0) {
                    Symbol sym = syms[0];
                    sym.setNamespace(ns);
                    String symName = sym.getName();
                    String prefix = ns.getName() + "::";
                    if (name != null) {
                        if (sym.getName().startsWith("FUN_") || sym.getName().startsWith("thunk_")) {
                            sym.setName(name, SourceType.USER_DEFINED);
                        }
                        symName = sym.getName();
                    }
                    if (symName.contains(prefix)) {
                        String sliced = symName.substring(
                                symName.lastIndexOf(prefix) + prefix.length());
                        sym.setName(sliced, SourceType.USER_DEFINED);
                    }
                } else {
                    if (name == null) name = String.format("FUN_%s", funcAddr);
                    symTab.createLabel(funcAddr, name, ns, SourceType.USER_DEFINED);
                }
                renameCount++;
            } catch (Exception e) {
                script.println("ERROR: Could not create label " + ns.getName(true) + "::" + name);
            }
        }

        // Create pointer array for this sub-vtable
        if (start != null && !mySlots.isEmpty()) {
            try {
                int arraySize = mySlots.size();
                Address arrayEnd = start.add((long) arraySize * PTR_SIZE - 1);

                ReferenceManager refMgr = program.getReferenceManager();
                Map<Address, List<Reference>> savedExtRefs = new HashMap<>();
                for (int j = 0; j < arraySize; j++) {
                    Address slotAddr = start.add((long) j * PTR_SIZE);
                    for (Reference ref : refMgr.getReferencesFrom(slotAddr)) {
                        if (ref instanceof ExternalReference) {
                            savedExtRefs.computeIfAbsent(slotAddr, k -> new ArrayList<>())
                                    .add(ref);
                        }
                    }
                }

                program.getListing().clearCodeUnits(start, arrayEnd, true);
                program.getListing().createData(start, new ArrayDataType(
                        PointerDataType.dataType, arraySize, PTR_SIZE));

                for (Map.Entry<Address, List<Reference>> entry : savedExtRefs.entrySet()) {
                    for (Reference ref : entry.getValue()) {
                        if (ref instanceof ExternalReference extRef) {
                            refMgr.addExternalReference(
                                    entry.getKey(),
                                    extRef.getLibraryName(),
                                    extRef.getLabel(),
                                    extRef.getExternalLocation().getAddress(),
                                    extRef.getSource(),
                                    ref.getOperandIndex(),
                                    ref.getReferenceType());
                        }
                    }
                }
            } catch (Exception e) {
                script.println("WARNING: Could not create vtable array at " + start);
            }
        }
    }
}