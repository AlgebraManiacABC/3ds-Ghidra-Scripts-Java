// Names vtable function entries from RTTI inheritance, working off vtable data
// already discovered by RTTIUtil.
//
//   RenameVTableFunctions renamer = new RenameVTableFunctions(this);
//   renamer.run(program, vtableRttiSlots, typeinfoAddresses, monitor, state);
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
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.util.*;
import java.util.regex.Pattern;

public class RenameVTableFunctions {

    private static final int PTR_SIZE = 4;

    // An adjustor thunk is a couple of instructions that fix up this and hand off.
    // Anything bigger that merely tail-calls a destructor is a real function.
    private static final int THUNK_MAX_BYTES = 32;

    // The placeholder names this script hands out. Secondary sub-vtables get the
    // function address appended, the same way the deleting destructor always has.
    private static final Pattern SLOT_PLACEHOLDER = Pattern.compile("F\\d{2,}(_.*)?");
    private static final Pattern DTOR_PLACEHOLDER = Pattern.compile("D[01](_.*)?");

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
    // operator delete addresses (thumb bit masked), found by agreement
    private final Set<Long> operatorDeleteAddrs = new HashSet<>();
    // __cxa_pure_virtual address (thumb bit masked)
    private long pureVirtualAddr = 0;
    private boolean externalPureVirtual = false;

    private final Set<String> processed = new HashSet<>();
    // class name -> code addresses writing its own or an ancestor's vtable pointer
    private final Map<String, Set<Address>> vtableWriterCache = new HashMap<>();
    // class name -> index of D1 in its primary sub-vtable, once known
    private final Map<String, Integer> dtorSlot = new HashMap<>();
    private final Map<String, Program> importedPrograms = new HashMap<>();

    private int renameCount = 0;
    private int skipCount = 0;
    private int pureVirtualCount = 0;

    // Which rule identified each destructor pair — printed once per run, so a single
    // run says where detection is working and where it is falling through.
    private int dtorByThunk = 0;
    private int dtorByDelete = 0;
    private int dtorByWrite = 0;
    private int dtorByInherit = 0;
    private int dtorNone = 0;

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
        operatorDeleteAddrs.clear();
        processed.clear();
        vtableWriterCache.clear();
        dtorSlot.clear();
        importedPrograms.clear();
        pureVirtualAddr = 0;
        externalPureVirtual = false;
        renameCount = 0;
        skipCount = 0;
        pureVirtualCount = 0;
        dtorByThunk = 0;
        dtorByDelete = 0;
        dtorByWrite = 0;
        dtorByInherit = 0;
        dtorNone = 0;

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

        // Step 4: If __cxa_pure_virtual wasn't found by symbol, detect by vtable analysis
        if (pureVirtualAddr == 0 && !externalPureVirtual) {
            detectPureVirtual();
        }
        if (pureVirtualAddr == 0 && !externalPureVirtual) {
            script.printf("    WARNING: No __cxa_pure_virtual for %s\n",program.getName());
        }

        // Step 5: Collect namespace objects
        collectNamespaces();

        // Step 6: Every destructor test reads a function body, so the slot targets
        // have to exist before any of them runs.
        ensureVtableFunctions();

        // Step 7: Note where operator delete lives, as a tiebreaker for D0
        collectOperatorDeletes();

        // Step 8: Process in topological order (Kahn's algorithm)

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

        // Step 9: Propagate discovered names upward through the hierarchy
        propagateNames();

        // Step 10: Add the mangled spelling of each name alongside it
        script.printf("    Mangled names added:    %d\n", emitMangledNames());

        script.printf("    Destructor slots:       %d thunk, %d op-delete, %d vtable-write, " +
                "%d inherited; %d sub-vtables with none\n",
                dtorByThunk, dtorByDelete, dtorByWrite, dtorByInherit, dtorNone);

        // Step 11: Assemble vtable structs for pretty decomp
        buildVtableStructs();

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

    /** Push a name found at slot N of a descendant onto every ancestor's slot N. */
    private int propagateNames() throws Exception {
        int count = 0;

        AddressSpace addressSpace = program.getMinAddress().getAddressSpace();
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

                    String name = getNonGenericName(funcAddr);
                    if (name == null) continue;
                    count += propagateToAncestors(className, sub, i, name);
                }
            }
        }

        return count;
    }

    /** A name this pass is free to overwrite: Ghidra's default, or its own placeholder. */
    private static boolean isRenameable(String name) {
        return name.startsWith("FUN_") || name.startsWith("thunk_") || isPlaceholder(name);
    }

    /** Any placeholder handed out by computeSlotNames(): F02, D1, D0_1 and friends. */
    private static boolean isPlaceholder(String name) {
        return isSlotPlaceholder(name) || isDestructorPlaceholder(name);
    }

    /** F02, or F07_1 in sub-vtable 1. */
    private static boolean isSlotPlaceholder(String name) {
        return SLOT_PLACEHOLDER.matcher(name).matches();
    }

    /** D1, or D0_1 in sub-vtable 1. */
    private static boolean isDestructorPlaceholder(String name) {
        return DTOR_PLACEHOLDER.matcher(name).matches();
    }

    /** A real name for this function, or null if it only carries a default or a placeholder. */
    private String getNonGenericName(Address funcAddr) {
        for (Symbol s : symTab.getSymbols(funcAddr)) {
            String name = s.getName();
            if (name.startsWith("FUN_") || name.startsWith("thunk_")) continue;
            if (isSlotPlaceholder(name) || isDestructorPlaceholder(name)) continue;
            if (!s.getParentNamespace().isGlobal()) {
                return name;
            }
        }
        return null;
    }

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
                                    sym.getName().startsWith("thunk_") ||
                                    isSlotPlaceholder(sym.getName()))) {   // never a D0/D1
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
    //  operator delete detection
    // ---------------------------------------------------------------

    /** Turn every vtable slot target into a function, once, up front. */
    private void ensureVtableFunctions() throws Exception {
        AddressSpace space = program.getMinAddress().getAddressSpace();
        for (Map.Entry<String, List<List<Long>>> entry : allVtableSlots.entrySet()) {
            List<Address> points = allVtableAddressPoints.get(entry.getKey());
            List<List<Long>> subVtables = entry.getValue();
            for (int v = 0; v < subVtables.size(); v++) {
                Address base = (points != null && v < points.size()) ? points.get(v) : null;
                List<Long> slots = subVtables.get(v);
                for (int i = 0; i < slots.size(); i++) {
                    long funcPtr = slots.get(i);
                    if (funcPtr == 0) continue;
                    if (base != null && isPureVirtualRef(base.add(4L * i))) continue;
                    ensureFunction(space.getAddress(funcPtr & ~1L));
                }
            }
        }
    }

    /**
     * Operator delete addresses, from symbols only. Do not try to infer these from
     * what deleting destructors call: teardown runs through a chain of helpers and
     * wrappers, all called by the same classes, so agreement cannot single out the
     * deallocator. Only a tiebreaker anyway — writesOwnVtable finds D1 structurally.
     */
    private void collectOperatorDeletes() {
        SymbolIterator named = symTab.getAllSymbols(false);
        List<String> found = new ArrayList<>();
        while (named.hasNext()) {
            Symbol sym = named.next();
            if (!isOperatorDelete(sym.getName()) || sym.isExternal()) continue;
            if (operatorDeleteAddrs.add(sym.getAddress().getOffset() & ~1L)) {
                found.add(sym.getName() + " at " + sym.getAddress());
            }
        }
        if (found.isEmpty()) {
            script.println("    No operator delete symbol; relying on vtable structure");
        } else {
            script.printf("    operator delete: %s\n", String.join(", ", found));
        }
    }
    // ---------------------------------------------------------------
    //  Mangled name emission
    // ---------------------------------------------------------------

    /**
     * Add each vtable function's Itanium-mangled spelling as a second label, for
     * ToggleMangledNames and ExportSymbols. Parameters are unknown this early, so
     * everything is mangled as taking void.
     */
    private int emitMangledNames() throws Exception {
        AddressSpace addressSpace = program.getMinAddress().getAddressSpace();
        Set<Address> seen = new HashSet<>();
        int count = 0;
        for (String className : processed) {
            List<List<Long>> subVtables = allVtableSlots.get(className);
            if (subVtables == null) continue;
            for (int v = 0; v < subVtables.size(); v++) {
                for (long funcPtr : subVtables.get(v)) {
                    if (funcPtr == 0) continue;
                    Address funcAddr = addressSpace.getAddress(funcPtr & ~1L);
                    if (!seen.add(funcAddr)) continue;
                    if (emitMangledName(funcAddr)) count++;
                }
            }
        }
        return count;
    }

    private boolean emitMangledName(Address funcAddr) {
        // A thunk reports the name of what it forwards to, so mangling it here would
        // stamp the target's symbol onto the wrong address.
        Function func = program.getListing().getFunctionAt(funcAddr);
        if (func != null && func.isThunk()) return false;

        Symbol entry = (func == null) ? null : func.getSymbol();
        Symbol named = null;
        Symbol stale = null;
        for (Symbol s : symTab.getSymbols(funcAddr)) {
            if (s.getName().startsWith("_Z")) {
                // Only revise a plain label this pass wrote; imported, hand-written
                // and user-toggled mangled names are real.
                if (s.getSource() != SourceType.ANALYSIS || s.equals(entry)) return false;
                stale = s;
                continue;
            }
            if (named == null && !s.getParentNamespace().isGlobal()) named = s;
        }
        if (named == null) return false;

        // A suffixed placeholder is an adjustor thunk, whose ABI name wraps the name
        // of the function it stands in for.
        String plain = named.getName();
        int subIdx = placeholderSubIndex(plain);
        if (subIdx > 0) plain = plain.substring(0, plain.lastIndexOf('_'));

        String mangled = mangle(named.getParentNamespace(), plain);
        if (mangled != null && subIdx > 0) {
            Integer adjustment = thunkAdjustment(funcAddr);
            mangled = (adjustment == null) ? null : asThunk(mangled, adjustment);
        }
        if (mangled == null) {
            if (stale != null) stale.delete();   // the name it came from is gone
            return false;
        }
        if (stale != null) {
            if (stale.getName().equals(mangled)) return false;
            stale.delete();
        }
        try {
            symTab.createLabel(funcAddr, mangled, program.getGlobalNamespace(),
                    SourceType.ANALYSIS);
            return true;
        } catch (Exception e) {
            script.println("WARNING: Could not label " + mangled + " at " + funcAddr);
            return false;
        }
    }

    /**
     * Itanium mangling for a nested member function taking no arguments: A::B::F02
     * becomes _ZN1A1B3F02Ev, D1/D0 become _ZN1A1BD1Ev / _ZN1A1BD0Ev. Null for
     * anything unspellable that way, such as templates and operators.
     */
    private String mangle(Namespace ns, String name) {
        List<String> parts = new ArrayList<>();
        for (Namespace n = ns; n != null && !n.isGlobal(); n = n.getParentNamespace()) {
            if (!isPlainIdentifier(n.getName())) return null;
            parts.addFirst(n.getName());
        }
        if (parts.isEmpty()) return null;

        StringBuilder sb = new StringBuilder("_ZN");
        for (String part : parts) sb.append(part.length()).append(part);

        if (name.equals("D0") || name.equals("D1")) {
            sb.append(name);
        } else if (isPlainIdentifier(name)) {
            sb.append(name.length()).append(name);
        } else {
            return null;
        }
        return sb.append("Ev").toString();
    }

    /** The sub-vtable index of a suffixed placeholder such as D1_1 or F05_2, else -1. */
    private static int placeholderSubIndex(String name) {
        if (!isPlaceholder(name)) return -1;
        int us = name.lastIndexOf('_');
        if (us < 0) return -1;
        try {
            return Integer.parseInt(name.substring(us + 1));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /**
     * The this-adjustment an adjustor thunk applies, read from its own first few
     * instructions. Null means there is no such instruction, which also answers
     * whether this is a thunk at all — a secondary slot can hold a real override.
     */
    private Integer thunkAdjustment(Address funcAddr) {
        Function func = program.getListing().getFunctionAt(funcAddr);
        if (func == null) return null;
        Register thisReg = program.getLanguage().getRegister("r0");
        if (thisReg == null) return null;
        try {
            InstructionIterator iter =
                    program.getListing().getInstructions(func.getBody(), true);
            for (int seen = 0; iter.hasNext() && seen < 4; seen++) {
                Instruction inst = iter.next();
                String mnemonic = inst.getMnemonicString().toLowerCase();
                boolean subtract = mnemonic.startsWith("sub");
                if (!subtract && !mnemonic.startsWith("add")) continue;
                if (!thisReg.equals(inst.getRegister(0))) continue;
                for (int op = 1; op < inst.getNumOperands(); op++) {
                    Scalar delta = inst.getScalar(op);
                    if (delta == null) continue;
                    long value = delta.getUnsignedValue();
                    return (int) (subtract ? -value : value);
                }
            }
        } catch (Exception e) {
            // fall through
        }
        return null;
    }

    /**
     * Wrap a mangled name as the non-virtual thunk forwarding to it: _ZN5AcFtrD1Ev
     * with a -104 adjustment becomes _ZThn104_N5AcFtrD1Ev.
     */
    private String asThunk(String mangled, int adjustment) {
        String offset = (adjustment < 0)
                ? "n" + (-(long) adjustment)
                : Long.toString(adjustment);
        return "_ZTh" + offset + "_" + mangled.substring(2);
    }

    private static boolean isPlainIdentifier(String s) {
        if (s.isEmpty() || Character.isDigit(s.charAt(0))) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c > 127) return false;
            if (!Character.isLetterOrDigit(c) && c != '_') return false;
        }
        return true;
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

        // Where this class writes its own vtable pointers — the destructor tell.
        Set<Address> vtableWriters = collectVtableWriters(className);

        // Primary sub-vtable
        List<Long> parentSlots = null;
        List<String> parents = parentMap.get(className);
        if (parents != null && !parents.isEmpty()) {
            parentSlots = vtableSlots.get(parents.getFirst());
        }
        processSubVtable(className, ns, addressPoint, mySlots, parentSlots, 0, vtableWriters);

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
                            parentAllSubVtables.get(s), s, vtableWriters);
                }
                return;
            }
            List<Address> myAddressPoints = allVtableAddressPoints.get(className);
            for (int s = 1; s < allSubVtables.size(); s++) {
                Address secAddr = (myAddressPoints != null && s < myAddressPoints.size())
                        ? myAddressPoints.get(s) : null;
                processSubVtable(className, ns, secAddr, allSubVtables.get(s), null, s, vtableWriters);
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
            processSubVtable(className, ns, secAddr, secondarySlots, baseSlots, s + 1, vtableWriters);
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
        return callsOperatorDelete(funcAddr, new HashSet<>(), 2);
    }

    /**
     * A deleting destructor calls operator delete. A secondary slot holds a thunk to
     * the real D0 rather than D0 itself, so hand-offs are followed one level further.
     */
    private boolean callsOperatorDelete(Address funcAddr, Set<Address> visited, int depth) {
        if (depth < 0 || !visited.add(funcAddr)) return false;
        try {
            Function func = program.getListing().getFunctionAt(funcAddr);
            if (func == null) return false;

            InstructionIterator iter =
                    program.getListing().getInstructions(func.getBody(), true);
            while (iter.hasNext()) {
                Instruction inst = iter.next();
                FlowType flow = inst.getFlowType();
                if (!flow.isCall() && !flow.isJump() && !flow.isTerminal()) continue;
                for (Reference ref : inst.getReferencesFrom()) {
                    Address target = ref.getToAddress();
                    if (target == null) continue;
                    if (operatorDeleteAddrs.contains(target.getOffset() & ~1L)) return true;
                    for (Symbol sym : symTab.getSymbols(target)) {
                        if (isOperatorDelete(sym.getName())) return true;
                        if (isDeletingDestructorName(sym.getName())) return true;
                    }
                    // Only out of an adjustor stub: chasing every call would walk most
                    // of the program, and mistake a member-destroying D1 for a thunk.
                    if (isThunkSized(func) && !func.getBody().contains(target)
                            && callsOperatorDelete(target, visited, depth - 1)) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            // fall through
        }
        return false;
    }

    /** Ghidra's label for operator delete, or its mangled spellings (_ZdlPv, _ZdaPv, ...). */
    private static boolean isOperatorDelete(String name) {
        return name.startsWith("operator.delete")
                || name.startsWith("_Zdl") || name.startsWith("_Zda");
    }

    /** A deleting-destructor name this script has already handed out: D0 or D0_<sub>. */
    private static boolean isDeletingDestructorName(String name) {
        return name.equals("D0") || name.startsWith("D0_");
    }

    private Namespace createNamespace(Program program, Namespace parent, String name) throws Exception {
        return program.getSymbolTable()
                .createNameSpace(parent, name, SourceType.USER_DEFINED);
    }

    /**
     * Name every slot of a sub-vtable: D1/D0 for the destructor pair, F02 onward for
     * the rest, so 00 and 01 stay reserved for that pair.
     *
     * D1 is the only function in a vtable that writes its own vtable pointer back
     * into this (a constructor does too, but is never virtual), and the ABI puts D0
     * in the next slot. Where optimisation elided those stores, the primary vtable
     * still preserves the base's slot ordering, so the index the base used carries
     * down the hierarchy.
     */
    private String[] computeSlotNames(List<Long> mySlots, Address start, int subIdx,
                                      Set<Address> vtableWriters, int inheritedDtorIdx)
            throws MemoryAccessException {
        AddressSpace addressSpace = program.getMinAddress().getAddressSpace();
        int n = mySlots.size();
        String[] kind = new String[n];      // "D0", "D1", or null for an ordinary slot

        for (int i = 0; i < n; i++) {
            long funcPtr = mySlots.get(i);
            if (funcPtr == 0) continue;
            if (start != null && isPureVirtualRef(start.add(4L * i))) continue;
            Address funcAddr = addressSpace.getAddress(funcPtr & ~1L);

            // Operator delete goes last: a D1 that frees a member reaches it too, so
            // on its own it cannot tell D1 from D0.
            String thunked;
            if (writesOwnVtable(funcAddr, vtableWriters)) { kind[i] = "D1"; dtorByWrite++; }
            else if ((thunked = thunkedDestructorKind(funcAddr)) != null) {
                kind[i] = thunked; dtorByThunk++;
            }
            else if (callsOperatorDelete(funcAddr)) { kind[i] = "D0"; dtorByDelete++; }
        }

        // Nothing at the base's destructor index means the stores were elided here.
        if (inheritedDtorIdx >= 0 && inheritedDtorIdx < n && kind[inheritedDtorIdx] == null) {
            kind[inheritedDtorIdx] = "D1";
            dtorByInherit++;
        }
        boolean found = false;
        for (String k : kind) if (k != null) { found = true; break; }
        if (!found && n > 0) dtorNone++;

        // D0 with D1 inlined stores the vtable pointer too, so both read as D1. In ABI
        // order the second of an adjacent pair is the deleting one.
        for (int i = 0; i + 1 < n; i++) {
            if ("D1".equals(kind[i]) && "D1".equals(kind[i + 1])) kind[i + 1] = "D0";
        }

        // The pair is adjacent, so whichever half was recognised fills in the other.
        for (int i = 0; i < n; i++) {
            if ("D1".equals(kind[i]) && i + 1 < n && kind[i + 1] == null) kind[i + 1] = "D0";
            if ("D0".equals(kind[i]) && i > 0 && kind[i - 1] == null) kind[i - 1] = "D1";
        }

        String[] names = new String[n];
        for (int i = 0; i < n; i++) {
            String base = (kind[i] != null) ? kind[i] : String.format("F%02d", i);
            // A secondary sub-vtable repeats the slot numbers of the primary, so its
            // names carry the sub-vtable index to stay distinct within the class.
            names[i] = (subIdx == 0) ? base : String.format("%s_%d", base, subIdx);
        }
        return names;
    }

    /**
     * Code writing the vtable pointer of this class or any ancestor. A destructor
     * stores its own and then each base's as it unwinds, and the compiler drops the
     * ones nothing observes, so the survivor may be an ancestor's.
     */
    private Set<Address> collectVtableWriters(String className) {
        return collectVtableWriters(className, new HashSet<>());
    }

    private Set<Address> collectVtableWriters(String className, Set<String> visited) {
        Set<Address> cached = vtableWriterCache.get(className);
        if (cached != null) return cached;
        if (!visited.add(className)) return Set.of();

        Set<Address> writers = new HashSet<>(ownVtableWriters(className));
        List<String> parents = parentMap.get(className);
        if (parents != null) {
            for (String parent : parents) {
                writers.addAll(collectVtableWriters(parent, visited));
            }
        }
        vtableWriterCache.put(className, writers);
        return writers;
    }

    /**
     * Code referring to one of this class's own vtable address points, plus one hop
     * back for the ARM literal pool the pointer is loaded from.
     */
    private Set<Address> ownVtableWriters(String className) {
        ReferenceManager refMgr = program.getReferenceManager();
        Set<Address> writers = new HashSet<>();
        List<Address> points = allVtableAddressPoints.get(className);
        if (points == null) return writers;
        for (Address point : points) {
            if (point == null) continue;
            for (Reference r : refMgr.getReferencesTo(point)) {
                Address from = r.getFromAddress();
                if (!writers.add(from)) continue;
                for (Reference lit : refMgr.getReferencesTo(from)) {
                    writers.add(lit.getFromAddress());
                }
            }
        }
        return writers;
    }

    private boolean writesOwnVtable(Address funcAddr, Set<Address> writers) {
        if (writers.isEmpty()) return false;
        Function func = program.getListing().getFunctionAt(funcAddr);
        if (func == null) return false;
        for (Address writer : writers) {
            if (func.getBody().contains(writer)) return true;
        }
        return false;
    }

    /**
     * D0/D1 if this slot holds a thunk to a function already named that. Targets are
     * named first, since a class's primary sub-vtable is processed before its
     * secondaries.
     */
    private String thunkedDestructorKind(Address funcAddr) {
        // Only the target's name counts, never this function's own: treating a name
        // this script wrote as evidence would make the first guess permanent.
        Function func = program.getListing().getFunctionAt(funcAddr);
        if (func == null || !isThunkSized(func)) return null;
        try {
            // By reference, not flow type: an adjustor thunk's branch carries a
            // CALL_RETURN override, so getFlowType() is not dependable here.
            InstructionIterator iter =
                    program.getListing().getInstructions(func.getBody(), true);
            while (iter.hasNext()) {
                Instruction inst = iter.next();
                for (Reference ref : inst.getReferencesFrom()) {
                    Address target = ref.getToAddress();
                    if (target == null || func.getBody().contains(target)) continue;
                    String kind = destructorKindAt(target);
                    if (kind != null) return kind;
                }
            }
        } catch (Exception e) {
            // fall through
        }
        return null;
    }

    /** The function at this address, disassembling and creating one if need be. */
    private Function ensureFunction(Address funcAddr) {
        Function func = program.getListing().getFunctionAt(funcAddr);
        if (func != null) return func;
        try {
            DisassembleCommand dCmd = new DisassembleCommand(funcAddr, null, true);
            dCmd.applyTo(program);
            CreateFunctionCmd fCmd = new CreateFunctionCmd(funcAddr);
            fCmd.applyTo(program);
            func = program.getListing().getFunctionAt(funcAddr);
        } catch (Exception e) {
            script.println("WARNING: Could not create function at " + funcAddr);
        }
        return func;
    }

    /** Small enough to be an adjustor stub rather than a function of its own. */
    private boolean isThunkSized(Function func) {
        return func.getBody().getNumAddresses() <= THUNK_MAX_BYTES;
    }

    /** "D0" / "D1" if some symbol here already carries that name, else null. */
    private String destructorKindAt(Address addr) {
        for (Symbol sym : symTab.getSymbols(addr)) {
            String name = sym.getName();
            if (name.equals("D0") || name.startsWith("D0_")) return "D0";
            if (name.equals("D1") || name.startsWith("D1_")) return "D1";
        }
        return null;
    }

    private void processSubVtable(String className, Namespace ns, Address start,
                                  List<Long> mySlots, List<Long> parentSlots,
                                  int subIdx, Set<Address> vtableWriters) throws Exception {
        int parentSlotCount = (parentSlots != null) ? parentSlots.size() : 0;
        AddressSpace addressSpace = program.getMinAddress().getAddressSpace();
        // The primary sub-vtable keeps the primary base's slot ordering, so a
        // destructor already located in that base is at the same index here.
        int inheritedDtorIdx = -1;
        if (subIdx == 0) {
            List<String> parents = parentMap.get(className);
            if (parents != null && !parents.isEmpty()) {
                inheritedDtorIdx = dtorSlot.getOrDefault(parents.getFirst(), -1);
            }
        }
        String[] slotNames =
                computeSlotNames(mySlots, start, subIdx, vtableWriters, inheritedDtorIdx);
        if (subIdx == 0) {
            for (int i = 0; i < slotNames.length; i++) {
                if ("D1".equals(slotNames[i])) {
                    dtorSlot.put(className, i);     // so this class's children inherit it
                    break;
                }
            }
        }
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

            Function func = ensureFunction(funcAddr);

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
                if (s.getParentNamespace().isGlobal()) continue;
                // Our own placeholder for this same class is not a real name, or the
                // pass could never revise its output. One in another class's namespace
                // still counts, so inherited slots keep what they were given.
                if (s.getParentNamespace().getID() == ns.getID()
                        && isPlaceholder(s.getName())) continue;
                alreadyNamed = true;
                existingNs = s.getParentNamespace();
                break;
            }
            if (alreadyNamed) {
                String existingClassName = existingNs.getName(true);
                if (isAncestorOf(existingClassName, className)) {
                    skipCount++;
                    continue;
                }
                String common = findCommonAncestor(existingClassName, className);
                Symbol oldSym = null;
                for (Symbol s : symTab.getSymbols(funcAddr)) {
                    if (s.getParentNamespace().getID() == existingNs.getID()) {
                        oldSym = s;
                        break;
                    }
                }
                // Only hoist a meaningful name. A slot placeholder means nothing in the
                // ancestor, which numbers its own vtable differently, and hoisting them
                // collapses unrelated functions onto one name.
                if (common != null && oldSym != null && !isPlaceholder(oldSym.getName())) {
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
                        String oldName = oldSym.getName();
                        oldSym.delete();
                        symTab.createLabel(funcAddr, oldName, commonNs,
                                SourceType.USER_DEFINED);
                        renameCount++;
                    }
                }
                skipCount++;
                continue;
            }

            String name = slotNames[i];
            try {
                SymbolTable symTab = program.getSymbolTable();
                // The function's own symbol: getSymbols() has no defined order, so
                // taking the first can land on a stray label instead and leave the
                // function untouched.
                Function nameFunc = program.getListing().getFunctionAt(funcAddr);
                Symbol sym = (nameFunc != null) ? nameFunc.getSymbol() : null;
                if (sym == null) {
                    Symbol[] syms = symTab.getSymbols(funcAddr);
                    if (syms != null && syms.length > 0) sym = syms[0];
                }
                if (sym != null) {
                    sym.setNamespace(ns);
                    String prefix = ns.getName() + "::";
                    if (isRenameable(sym.getName())) {
                        sym.setName(name, SourceType.USER_DEFINED);
                    }
                    String symName = sym.getName();
                    if (symName.contains(prefix)) {
                        String sliced = symName.substring(
                                symName.lastIndexOf(prefix) + prefix.length());
                        sym.setName(sliced, SourceType.USER_DEFINED);
                    }
                } else {
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

    private static final CategoryPath VTABLE_PATH = new CategoryPath("/vtables");
    private static final CategoryPath VTFUNC_PATH  = new CategoryPath("/vtables/functions");

    private DataType prepareBasicFuncDef(Program program) {
        DataTypeManager dtm = program.getDataTypeManager();
        int ptrSize = program.getDefaultPointerSize();
        FunctionDefinitionDataType generic = new FunctionDefinitionDataType(VTFUNC_PATH, "vfunc");
        generic.setReturnType(new PointerDataType(DataType.VOID, ptrSize));
        generic.setArguments(new ParameterDefinitionImpl("this",
                new PointerDataType(DataType.VOID, ptrSize), null));
        generic.setVarArgs(true);
        return new PointerDataType(dtm.resolve(generic, DataTypeConflictHandler.KEEP_HANDLER), ptrSize);
    }

    private void applyVtableStruct(Address point, Structure vt) throws InvalidInputException, DuplicateNameException {
        ReferenceManager refMgr = program.getReferenceManager();
        Map<Address, List<Reference>> saved = new HashMap<>();
        for (int j = 0; j * PTR_SIZE < vt.getLength(); j++) {
            Address a = point.add((long) j * PTR_SIZE);
            for (Reference ref : refMgr.getReferencesFrom(a)) {
                if (ref instanceof ExternalReference) {
                    saved.computeIfAbsent(a, k -> new ArrayList<>()).add(ref);
                }
            }
        }
        try {
            program.getListing().clearCodeUnits(point, point.add(vt.getLength() - 1L), true);
            program.getListing().createData(point, vt);
        } catch (Exception e) {
            script.println("WARNING: Could not apply vtable struct at " + point);
            return;
        }
        for (var e : saved.entrySet()) {
            for (Reference ref : e.getValue()) {
                if (ref instanceof ExternalReference ext) {
                    refMgr.addExternalReference(e.getKey(), ext.getLibraryName(), ext.getLabel(),
                            ext.getExternalLocation().getAddress(), ext.getSource(),
                            ref.getOperandIndex(), ref.getReferenceType());
                }
            }
        }
    }

    private void buildVtableStructs() throws Exception {
        DataTypeManager dtm = program.getDataTypeManager();
        AddressSpace space = program.getMinAddress().getAddressSpace();
        DataType vFuncPtr = prepareBasicFuncDef(program);   // move this over from RTTIUtil
        int built = 0;

        for (Map.Entry<String, List<List<Long>>> entry : allVtableSlots.entrySet()) {
            String className = entry.getKey();
            List<List<Long>> subVtables = entry.getValue();
            List<Address> points = allVtableAddressPoints.get(className);
            if (points == null || points.size() != subVtables.size()) continue;
            Structure primaryVt = null;

            Namespace ns = classNamespaces.get(className);
            if (ns == null) continue;
            GhidraClass cls;
            if (ns instanceof GhidraClass gc) {
                cls = gc;
            } else {
                try {
                    cls = symTab.convertNamespaceToClass(ns);
                } catch (Exception e) {
                    script.println("    WARNING: skipping vtable struct for " + className);
                    continue;
                }
            }

            for (int v = 0; v < subVtables.size(); v++) {
                List<Long> slots = subVtables.get(v);
                Address point = points.get(v);
                if (slots.isEmpty()) continue;

                String flat = cls.getName(true).replace("::", "_");
                String structName = (v == 0) ? flat + "_vtable" : flat + "_vtable_" + v;
                StructureDataType s = new StructureDataType(VTABLE_PATH, structName, 0, dtm);

                Set<String> used = new HashSet<>();
                for (int i = 0; i < slots.size(); i++) {
                    s.add(vFuncPtr, fieldNameFor(space, point, slots.get(i), i, used), "slot " + i);
                }

                Structure resolved = (Structure) dtm.resolve(s, DataTypeConflictHandler.REPLACE_HANDLER);
                applyVtableStruct(point, resolved);
                if (v == 0) primaryVt = resolved;
                built++;
            }

            if (primaryVt != null) linkClassStruct(dtm, cls, primaryVt);
        }
        script.printf("    Vtable structs built:   %d\n", built);
    }

    private void linkClassStruct(DataTypeManager dtm, GhidraClass cls, Structure vt) {
        Structure cs = VariableUtilities.findExistingClassStruct(cls, dtm);
        if (cs == null) {
            Structure placeholder = VariableUtilities.findOrCreateClassStruct(cls, dtm);
            if (placeholder == null) {          // name collides with an unrelated data type
                script.println("    WARNING: no class struct available for " + cls.getName(true));
                return;
            }
            cs = (Structure) dtm.resolve(placeholder, DataTypeConflictHandler.KEEP_HANDLER);
        }

        DataType vtPtr = new PointerDataType(vt, PTR_SIZE);
        try {
            if (cs.getLength() < PTR_SIZE) {
                cs.insertAtOffset(0, vtPtr, PTR_SIZE, "vtbl", "vtable pointer");
            } else {
                cs.replaceAtOffset(0, vtPtr, PTR_SIZE, "vtbl", "vtable pointer");
            }
        } catch (Exception e) {
            script.println("    WARNING: could not set vtbl on " + cls.getName() + ": " + e.getMessage());
        }
    }

    private String fieldNameFor(AddressSpace space, Address point, long funcPtr,
                                int i, Set<String> used) throws MemoryAccessException {
        Address slotAddr = point.add(4L * i);
        String base = null;

        // external label first — an imported virtual also reads as funcPtr == 0
        for (Reference r : program.getReferenceManager().getReferencesFrom(slotAddr)) {
            if (r instanceof ExternalReference ext && ext.getLabel() != null) {
                base = ext.getLabel();
                break;
            }
        }
        if (base == null && (isPureVirtualRef(slotAddr) || funcPtr == 0)) {
            base = "__cxa_pure_virtual";
        }
        if (base == null) {
            Function f = program.getFunctionManager()
                    .getFunctionAt(space.getAddress(funcPtr & ~1L));
            if (f != null) base = f.getName();
        }
        if (base == null) base = "slot";

        base = base.replaceAll("[^A-Za-z0-9_]", "_");
        if (base.isEmpty() || Character.isDigit(base.charAt(0))) base = "_" + base;

        String name = base;
        int n = 1;
        while (!used.add(name)) name = base + "_" + (n++);   // overloads collide otherwise
        return name;
    }
}