// Utility class for RTTI discovery, demangling, struct application, and vtable location.
//
// Usage (from a GhidraScript):
//   RTTIUtilities rtti = new RTTIUtilities(this);
//   rtti.run();
//   // Results available via getters
//
// @category RTTI
// @author Claude (for AlgebraManiacABC)

package util;

import ghidra.app.cmd.data.CreateStringCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

import java.util.*;

import static util.Demangler.DemangleAndNameNamespace;

public class RTTIUtil {

    private static final int PTR_SIZE = 4;
    private static final CategoryPath TYPE_INFO_PATH = new CategoryPath("/type_info");

    private final GhidraScript script;

    // __cxxabiv1 typeinfo vtable addresses -> base RTTI type name
    // e.g. 0x12345678 -> "__class_type_info"
    private final Map<Long, String> cxxabiVtableAddrs = new LinkedHashMap<>();

    // Discovered typeinfo struct locations -> base RTTI type name
    private final Map<Long, String> discoveredTypeinfos = new LinkedHashMap<>();

    // Discovered typeinfo struct locations -> struct size (for exclusion in vtable scan)
    private final Map<Long, Integer> typeinfoStructSizes = new LinkedHashMap<>();

    // Discovered vtable RTTI slot addresses (address of the pointer-to-typeinfo inside a vtable)
    // Maps: vtable RTTI slot address -> typeinfo struct address it points to
    private final Map<Long, Long> vtableRttiSlots = new LinkedHashMap<>();

    // Name string addresses collected from typeinfo offset 4
    private final Set<Long> nameStringAddrs = new LinkedHashSet<>();

    public RTTIUtil(GhidraScript script) {
        this.script = script;
    }

    // ---------------------------------------------------------------
    //  Public API
    // ---------------------------------------------------------------

    /**
     * Run the full discovery pipeline: find typeinfos, demangle names,
     * create/apply struct types, discover vtables.
     */
    public void run(Program program) throws Exception {
        script.println("=== RTTI Discovery Pipeline ===\n");

        script.println("[1] Finding __cxxabiv1 typeinfo vtable addresses...");
        findCxxabiVtableAddresses(program);
        script.println("    Found " + cxxabiVtableAddrs.size() + " vtable address(es).\n");

        if (cxxabiVtableAddrs.isEmpty()) {
            script.printerr("No __cxxabiv1 typeinfo vtable addresses found. Cannot proceed.");
            return;
        }

        script.println("[2] Scanning .rodata for typeinfo structs...");
        scanForTypeinfoStructs(program);
        script.println("    Found " + discoveredTypeinfos.size() + " typeinfo struct(s).\n");

        script.println("[3] Demangling RTTI name strings...");
        demangleNames(program);
        script.println("    Processed " + nameStringAddrs.size() + " name string(s).\n");

        script.println("[4] Ensuring typeinfo data types exist...");
        ensureTypeInfoDataTypes(program);
        script.println("    Done.\n");

        script.println("[5] Applying struct types to discovered typeinfos...");
        applyTypeinfoStructs(program);
        script.println("    Done.\n");

        script.println("[6] Discovering vtables in .rodata...");
        discoverVtables(program);
        script.println("    Found " + vtableRttiSlots.size() + " vtable(s).\n");

        script.println("=== RTTI Discovery Complete ===");
    }

    /** Returns the map of vtable RTTI slot address -> typeinfo address. */
    public Map<Long, Long> getVtableRttiSlots() {
        return Collections.unmodifiableMap(vtableRttiSlots);
    }

    /** Returns the map of typeinfo address -> RTTI base type name. */
    public Map<Long, String> getDiscoveredTypeinfos() {
        return Collections.unmodifiableMap(discoveredTypeinfos);
    }

    /** Returns the set of typeinfo struct addresses (for external use). */
    public Set<Long> getTypeinfoAddresses() {
        return Collections.unmodifiableSet(discoveredTypeinfos.keySet());
    }

    // ---------------------------------------------------------------
    //  Step 1: Find __cxxabiv1 typeinfo vtable addresses
    // ---------------------------------------------------------------

    private void findCxxabiVtableAddresses(Program program) {
        SymbolTable symTable = program.getSymbolTable();

        // Search internal symbols
        SymbolIterator iter = symTable.getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            String rttiType = classifySymbolName(sym.getName());
            if (rttiType != null) {
                long addr = sym.getAddress().getOffset();
                if (!cxxabiVtableAddrs.containsKey(addr)) {
                    cxxabiVtableAddrs.put(addr, rttiType);
                    script.println("    Internal: " + sym.getName() +
                            " at 0x" + Long.toHexString(addr) + " -> " + rttiType);
                }
            }
        }

        // Search external references
        ReferenceManager refMan = program.getReferenceManager();
        ReferenceIterator refIter = refMan.getExternalReferences();
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (ref instanceof ExternalReference extRef) {
                String rttiType = classifySymbolName(extRef.getLabel());
                if (rttiType != null) {
                    Address extAddr = extRef.getExternalLocation().getAddress();
                    if (extAddr != null) {
                        long addr = extAddr.getOffset();
                        if (!cxxabiVtableAddrs.containsKey(addr)) {
                            cxxabiVtableAddrs.put(addr, rttiType);
                            script.println("    External: " + extRef.getLabel() +
                                    " at 0x" + Long.toHexString(addr) + " -> " + rttiType);
                        }
                    }
                }
            }
        }
    }

    /**
     * Check if a symbol name refers to a __cxxabiv1 typeinfo class.
     * Returns the base type name or null.
     */
    private String classifySymbolName(String name) {
        if (name == null) return null;
        // Order matters: check __vmi first, then __si, then __class
        // to avoid false matches (e.g. "__class" matching inside "__si_class")
        if (name.contains("__vmi_class_type_info")) return "__vmi_class_type_info";
        if (name.contains("__si_class_type_info")) return "__si_class_type_info";
        if (name.contains("__class_type_info")) return "__class_type_info";
        return null;
    }

    // ---------------------------------------------------------------
    //  Step 2: Scan .rodata for typeinfo structs
    // ---------------------------------------------------------------

    private void scanForTypeinfoStructs(Program program) throws Exception {
        Memory mem = program.getMemory();
        MemoryBlock rodata = findRodataBlock(program);
        if (rodata == null) {
            script.printerr("Could not find .rodata block!");
            return;
        }

        Address start = rodata.getStart();
        Address end = rodata.getEnd();
        long startOff = start.getOffset();
        long endOff = end.getOffset();

        // Scan every 4-byte-aligned address for values matching __cxxabiv1 vtable addresses
        for (long off = startOff; off + PTR_SIZE <= endOff + 1; off += PTR_SIZE) {
            Address addr = start.getNewAddress(off);
            long value = Integer.toUnsignedLong(mem.getInt(addr));

            String rttiType = cxxabiVtableAddrs.get(value);
            if (rttiType != null) {
                discoveredTypeinfos.put(off, rttiType);
            }

            // Also check if there's an external reference at this address
            // that resolves to one of the __cxxabiv1 vtables
            if (rttiType == null) {
                rttiType = checkExternalRefForCxxabi(program, addr);
                if (rttiType != null) {
                    discoveredTypeinfos.put(off, rttiType);
                }
            }
        }
    }

    /**
     * Check if an address has an external reference pointing to a __cxxabiv1 typeinfo vtable.
     */
    private String checkExternalRefForCxxabi(Program program, Address addr) {
        ReferenceManager refMgr = program.getReferenceManager();
        for (Reference ref : refMgr.getReferencesFrom(addr)) {
            if (ref instanceof ExternalReference extRef) {
                String label = extRef.getLabel();
                String rttiType = classifySymbolName(label);
                if (rttiType != null) return rttiType;
            }
        }
        return null;
    }

    private MemoryBlock findRodataBlock(Program program) {
        Memory mem = program.getMemory();
        for (MemoryBlock block : mem.getBlocks()) {
            String name = block.getName();
            if (name.equals(".rodata") || name.equals("rodata")) {
                return block;
            }
        }
        // Fallback: look for a read-only, non-executable block
        for (MemoryBlock block : mem.getBlocks()) {
            if (block.isRead() && !block.isWrite() && !block.isExecute()) {
                return block;
            }
        }
        return null;
    }

    // ---------------------------------------------------------------
    //  Step 3: Demangle RTTI name strings
    // ---------------------------------------------------------------

    private void demangleNames(Program program) throws Exception {
        Memory mem = program.getMemory();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        SymbolTable symTable = program.getSymbolTable();

        for (Map.Entry<Long, String> entry : discoveredTypeinfos.entrySet()) {
            long tiAddr = entry.getKey();
            Address structAddr = space.getAddress(tiAddr);

            // Read __name pointer at offset 4
            long namePtr = Integer.toUnsignedLong(mem.getInt(structAddr.add(PTR_SIZE)));
            Address nameAddr = space.getAddress(namePtr);
            nameStringAddrs.add(namePtr);

            // Check if there's string data at the name address
            Listing listing = program.getListing();
            Data data = listing.getDataAt(nameAddr);
            if (data == null || !(data.getValue() instanceof String)) {
                // Try to create a string
                try {
                    listing.clearCodeUnits(nameAddr, nameAddr, true);
                    CreateStringCmd cmd = new CreateStringCmd(nameAddr);
                    cmd.applyTo(program);
                    data = listing.getDataAt(nameAddr);
                } catch (Exception e) {
                    script.println("    WARNING: Could not create string at 0x" +
                            Long.toHexString(namePtr));
                    continue;
                }
            }

            SymbolTable symTab = program.getSymbolTable();
            if (data != null && data.getValue() instanceof String name) {
                // Set symbol name with _ZTS prefix for demangling
                String mangled = "_ZTS" + name;
                Symbol[] syms = symTab.getSymbols(nameAddr);
                if (syms == null || syms.length == 0) {
                    symTable.createLabel(nameAddr, mangled, SourceType.USER_DEFINED);
                } else {
                    syms[0].setName(mangled, SourceType.DEFAULT);
                }
                DemangleAndNameNamespace(program, nameAddr, script.getMonitor());
            }
        }
    }

    // ---------------------------------------------------------------
    //  Step 4: Ensure typeinfo data types exist
    // ---------------------------------------------------------------

    private void ensureTypeInfoDataTypes(Program program) throws Exception {
        DataTypeManager dtm = program.getDataTypeManager();
        int ptrSize = program.getDefaultPointerSize();

        int txId = dtm.startTransaction("Create __cxxabiv1 typeinfo structs");
        try {
            createBaseClassTypeInfo(dtm, ptrSize);
            createClassTypeInfo(dtm, ptrSize);
            createSiClassTypeInfo(dtm, ptrSize);

            // Determine max base count needed
            Set<Integer> baseCounts = new HashSet<>();
            Memory mem = program.getMemory();
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            for (Map.Entry<Long, String> entry : discoveredTypeinfos.entrySet()) {
                if (entry.getValue().equals("__vmi_class_type_info")) {
                    Address addr = space.getAddress(entry.getKey());
                    int baseCount = mem.getInt(addr.add(12));
                    baseCounts.add(baseCount);
                }
            }
            for (int count : baseCounts) {
                createVmiClassTypeInfo(dtm, ptrSize, count);
            }

            if (baseCounts.isEmpty()) {
                // Create common variants anyway
                createVmiClassTypeInfo(dtm, ptrSize, 1);
                createVmiClassTypeInfo(dtm, ptrSize, 2);
                createVmiClassTypeInfo(dtm, ptrSize, 3);
            }
        } finally {
            dtm.endTransaction(txId, true);
        }
    }

    private PointerDataType ptr(DataType dt, int ptrSize) {
        return new PointerDataType(dt, ptrSize);
    }

    private boolean dtExists(DataTypeManager dtm, String name) {
        return dtm.getDataType(TYPE_INFO_PATH, name) != null;
    }

    private void createBaseClassTypeInfo(DataTypeManager dtm, int ptrSize) {
        String name = "__base_class_type_info";
        if (dtExists(dtm, name)) return;
        StructureDataType s = new StructureDataType(TYPE_INFO_PATH, name, 0);
        s.add(ptr(DataType.VOID, ptrSize), "__base_type", "const __class_type_info *");
        s.add(LongDataType.dataType, "__offset_flags", "offset and info bitfield");
        dtm.resolve(s, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    private void createClassTypeInfo(DataTypeManager dtm, int ptrSize) {
        String name = "__class_type_info";
        if (dtExists(dtm, name)) return;
        StructureDataType s = new StructureDataType(TYPE_INFO_PATH, name, 0);
        s.add(ptr(DataType.VOID, ptrSize), "__vtable_ptr", "typeinfo vtable pointer");
        s.add(ptr(CharDataType.dataType, ptrSize), "__name", "mangled name");
        dtm.resolve(s, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    private void createSiClassTypeInfo(DataTypeManager dtm, int ptrSize) {
        String name = "__si_class_type_info";
        if (dtExists(dtm, name)) return;
        StructureDataType s = new StructureDataType(TYPE_INFO_PATH, name, 0);
        s.add(ptr(DataType.VOID, ptrSize), "__vtable_ptr", "typeinfo vtable pointer");
        s.add(ptr(CharDataType.dataType, ptrSize), "__name", "mangled name");
        s.add(ptr(DataType.VOID, ptrSize), "__base_type", "const __class_type_info *");
        dtm.resolve(s, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    private void createVmiClassTypeInfo(DataTypeManager dtm, int ptrSize, int baseCount) {
        String name = "__vmi_class_type_info_" + baseCount;
        if (dtExists(dtm, name)) return;
        DataType baseClassTI = dtm.getDataType(TYPE_INFO_PATH, "__base_class_type_info");
        if (baseClassTI == null) {
            script.printerr("ERROR: __base_class_type_info not found.");
            return;
        }
        StructureDataType s = new StructureDataType(TYPE_INFO_PATH, name, 0);
        s.add(ptr(DataType.VOID, ptrSize), "__vtable_ptr", "typeinfo vtable pointer");
        s.add(ptr(CharDataType.dataType, ptrSize), "__name", "mangled name");
        s.add(UnsignedIntegerDataType.dataType, "__flags", "diamond / non-diamond flags");
        s.add(UnsignedIntegerDataType.dataType, "__base_count", "number of direct bases");
        ArrayDataType baseArray = new ArrayDataType(baseClassTI, baseCount, baseClassTI.getLength());
        s.add(baseArray, "__base_info", "__base_class_type_info[" + baseCount + "]");
        dtm.resolve(s, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    // ---------------------------------------------------------------
    //  Step 5: Apply struct types to discovered typeinfos
    // ---------------------------------------------------------------

    private void applyTypeinfoStructs(Program program) throws Exception {
        Memory mem = program.getMemory();
        DataTypeManager dtm = program.getDataTypeManager();
        Listing listing = program.getListing();
        SymbolTable symTable = program.getSymbolTable();
        ReferenceManager refMgr = program.getReferenceManager();
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

        for (Map.Entry<Long, String> entry : discoveredTypeinfos.entrySet()) {
            long tiAddrOff = entry.getKey();
            String rttiType = entry.getValue();
            Address addr = space.getAddress(tiAddrOff);

            // Determine struct name
            String structName = rttiType;
            if (rttiType.equals("__vmi_class_type_info")) {
                int baseCount = mem.getInt(addr.add(12));
                structName = "__vmi_class_type_info_" + baseCount;
            }

            DataType dt = dtm.getDataType(TYPE_INFO_PATH, structName);
            if (dt == null) {
                script.printerr("Data type not found: " + structName);
                continue;
            }

            int structSize = dt.getLength();
            typeinfoStructSizes.put(tiAddrOff, structSize);
            Address structEnd = addr.add(structSize - 1);

            // Save external references before clearing
            Map<Address, List<Reference>> savedExtRefs = new HashMap<>();
            for (long offset = 0; offset < structSize; offset += PTR_SIZE) {
                Address fieldAddr = addr.add(offset);
                for (Reference ref : refMgr.getReferencesFrom(fieldAddr)) {
                    if (ref instanceof ExternalReference) {
                        savedExtRefs.computeIfAbsent(fieldAddr, k -> new ArrayList<>())
                                .add(ref);
                    }
                }
            }

            // Clear and apply struct
            listing.clearCodeUnits(addr, structEnd, false);
            listing.createData(addr, dt);

            // Restore external references
            for (Map.Entry<Address, List<Reference>> refEntry : savedExtRefs.entrySet()) {
                Address fieldAddr = refEntry.getKey();
                for (Reference ref : refEntry.getValue()) {
                    if (ref instanceof ExternalReference extRef) {
                        refMgr.addExternalReference(
                                fieldAddr,
                                extRef.getLibraryName(),
                                extRef.getLabel(),
                                extRef.getExternalLocation().getAddress(),
                                extRef.getSource(),
                                ref.getOperandIndex(),
                                ref.getReferenceType());
                    }
                }
            }

            // Label the typeinfo struct with its class namespace
            long namePtr = Integer.toUnsignedLong(mem.getInt(addr.add(PTR_SIZE)));
            Address namePtrAddr = space.getAddress(namePtr);

            Namespace parentNs = null;
            for (Symbol sym : symTable.getSymbols(namePtrAddr)) {
                Namespace ns = sym.getParentNamespace();
                if (ns != null && !ns.isGlobal()) {
                    parentNs = ns;
                    break;
                }
            }

            if (parentNs != null) {
                boolean found = false;
                for (Symbol sym : symTable.getSymbols(addr)) {
                    if (sym.getParentNamespace().equals(parentNs) &&
                            sym.getName().equals("typeinfo")) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    program.getSymbolTable().createLabel(addr, "typeinfo",
                            parentNs, SourceType.USER_DEFINED);
                }
//                script.println("    " + parentNs.getName(true) + "::typeinfo at 0x" +
//                        Long.toHexString(tiAddrOff));
            }
        }
    }

    // ---------------------------------------------------------------
    //  Step 6: Discover vtables
    // ---------------------------------------------------------------

    private void discoverVtables(Program program) throws Exception {
        Memory mem = program.getMemory();
        MemoryBlock rodata = findRodataBlock(program);
        if (rodata == null) {
            script.printerr("Could not find .rodata block!");
            return;
        }

        Set<Long> typeinfoAddrSet = discoveredTypeinfos.keySet();

        // Precompute set of all 4-byte-aligned addresses inside typeinfo structs
        Set<Long> excludedAddrs = new HashSet<>();
        for (Map.Entry<Long, Integer> entry : typeinfoStructSizes.entrySet()) {
            long structStart = entry.getKey();
            int structSize = entry.getValue();
            for (long off = structStart; off < structStart + structSize; off += PTR_SIZE) {
                excludedAddrs.add(off);
            }
        }

        Address start = rodata.getStart();
        Address end = rodata.getEnd();
        long startOff = start.getOffset();
        long endOff = end.getOffset();

        for (long off = startOff; off + PTR_SIZE <= endOff + 1; off += PTR_SIZE) {
            if (excludedAddrs.contains(off)) continue;

            Address addr = start.getNewAddress(off);
            long value = Integer.toUnsignedLong(mem.getInt(addr));

            if (typeinfoAddrSet.contains(value)) {
                vtableRttiSlots.put(off, value);
            }
        }
    }
}