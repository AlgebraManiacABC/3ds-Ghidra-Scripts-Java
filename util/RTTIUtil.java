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
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;

import java.nio.charset.StandardCharsets;
import java.util.*;

import static util.Demangler.DemangleAndNameNamespace;

public class RTTIUtil {

    private static final int PTR_SIZE = 4;
    private static final CategoryPath TYPE_INFO_PATH = new CategoryPath("/type_info");

    private final GhidraScript script;

    // __cxxabiv1 typeinfo vtable addresses -> base RTTI type name
    // e.g. 0x12345678 -> "__class_type_info"
    private final Map<String, Map<Address, String>> cxxabiVtableAddrs = new LinkedHashMap<>();

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
        // Clear per-module state (but keep cxxabiVtableAddrs across runs)
        discoveredTypeinfos.clear();
        typeinfoStructSizes.clear();
        vtableRttiSlots.clear();
        nameStringAddrs.clear();
        script.printf("=== RTTI Discovery Pipeline for %s ===\n",program.getName());

        findCxxabiVtableAddresses(program);

        if (cxxabiVtableAddrs.isEmpty()) {
            script.printerr("No __cxxabiv1 typeinfo vtable addresses found. Cannot proceed.");
            return;
        }

        scanForTypeinfoStructs(program);

        demangleNames(program);

        ensureTypeInfoDataTypes(program);

        applyTypeinfoStructs(program);

        discoverVtables(program);

        script.println("    Local vtable addresses: " +
                cxxabiVtableAddrs.get(program.getName()).size());
        script.println("    Typeinfo structs:       " +
                discoveredTypeinfos.size());
        script.println("    Vtables:                " +
                vtableRttiSlots.size());
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

    // Known mangled names for the __cxxabiv1 typeinfo classes
    private static final Map<String, String> CXXABI_MANGLED_NAMES = Map.of(
            "N10__cxxabiv117__class_type_infoE", "__class_type_info",
            "N10__cxxabiv120__si_class_type_infoE", "__si_class_type_info",
            "N10__cxxabiv121__vmi_class_type_infoE", "__vmi_class_type_info"
    );

    private Map<Address, String> scanForTypeInfoRefs(Program program) throws Exception {
        Map<Address, String> refs = new HashMap<>();
        Memory mem = program.getMemory();
        MemoryBlock rodata = findRodataBlock(program);
        if (rodata == null) {
            script.printerr("Could not find .rodata block!");
            return null;
        }
        Address startOff = rodata.getStart();
        Address endOff = rodata.getEnd();

        // First pass: find all typeinfo string bases
        Map<Address, String> typeInfoNameAddrs = new HashMap<>();
        for (var entry : CXXABI_MANGLED_NAMES.entrySet()) {
            byte[] pattern = entry.getKey().getBytes(StandardCharsets.US_ASCII);
            Address addr = mem.getMinAddress();
            while (addr != null) {
                addr = mem.findBytes(addr, pattern, null, true, script.getMonitor());
                if (addr == null) break;
                typeInfoNameAddrs.put(addr, entry.getValue());
                addr = addr.add(1);
            }
        }

        // Second pass: find references, excluding hits inside the cxxabi typeinfo structs themselves
        Map<Address, String> typeinfoStructAddrs = new HashMap<>();
        for (var base : typeInfoNameAddrs.entrySet()) {
            long namePtr = base.getKey().getOffset();
            for (Address off = startOff; off.add(PTR_SIZE).compareTo(endOff) <= 0; off = off.add(PTR_SIZE)) {
                long here = mem.getInt(off);
                if (here != namePtr) continue;
                // Otherwise, this is a reference to the typeinfo-name.
                typeinfoStructAddrs.put(off.subtract(4), base.getValue());
            }
        }

        // Final pass: get references to the typeinfo structs, excluding inside the cxxabi structs
        SymbolTable symTab = program.getSymbolTable();
        for (Map.Entry<Address,String> entry : typeinfoStructAddrs.entrySet()) {
            long tiPtr = entry.getKey().getOffset();
            for (Address off = startOff; off.add(PTR_SIZE).compareTo(endOff) <= 0; off = off.add(PTR_SIZE)) {
                long here = mem.getInt(off);
                if (here != tiPtr) continue;
                // Otherwise, this is a reference to the typeinfo struct!
                if (!isInsideTypeInfoBase(off, typeinfoStructAddrs)) {
                    // A typeinfo's vptr stores vtable+8 (the first virtual function slot),
                    // which is off+4 here. off itself (vtable+4, the vtable's own typeinfo
                    // slot) is never stored anywhere, so registering it only adds noise.
                    refs.put(off.add(4), entry.getValue());
                    // Label the head and first ptr
                    symTab.createLabel(off.add(4),entry.getValue() + "_vtable", SourceType.USER_DEFINED);
                    symTab.createLabel(off.subtract(4),entry.getValue() + "::vtable", SourceType.USER_DEFINED);
                }
            }
        }

        return refs;
    }

    private boolean isInsideTypeInfoBase(Address addr, Map<Address, String> bases) {
        for (Address base : bases.keySet()) {
            long diff = addr.subtract(base);
            if (Math.abs(diff) < 12) return true;
        }
        return false;
    }

    private void findCxxabiVtableAddresses(Program program) {
        // Bootstrap from name strings first
        try {
            var map = scanForTypeInfoRefs(program);
            if (map == null) throw new NullPointerException();
            cxxabiVtableAddrs.computeIfAbsent(program.getName(),
                    s -> new HashMap<>()).putAll(map);
//            script.println("    === cxxabiVtableAddrs contents ===");
//            for (Map.Entry<String, Map<Address, String>> entry : cxxabiVtableAddrs.entrySet()) {
//                if (entry.getValue().isEmpty()) continue;
//                script.printf("    %s:\n", entry.getKey());
//                for (Map.Entry<Address, String> subentry : entry.getValue().entrySet()) {
//                    script.printf("        %s : %s\n", subentry.getKey(), subentry.getValue());
//                }
//            }
        } catch (Exception e) {
            script.println("    WARNING: Bootstrap from name strings failed: " + e.getMessage());
        }
        SymbolTable symTable = program.getSymbolTable();

        // Search internal symbols
        SymbolIterator iter = symTable.getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            String rttiType = classifySymbolName(sym.getName());
            if (rttiType != null) {
                Address addr = sym.getAddress();
                if (!cxxabiVtableAddrs.computeIfAbsent(program.getName(),
                        s -> new HashMap<>()).containsKey(addr)) {
                    cxxabiVtableAddrs.get(program.getName()).put(addr, rttiType);
                }
            }
        }

        // Search external references
        ReferenceManager refMan = program.getReferenceManager();
        ReferenceIterator refIter = refMan.getExternalReferences();
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (ref instanceof ExternalReference extRef) {
                ExternalManager extMan = program.getExternalManager();
                String extPath = extMan.getExternalLibraryPath(extRef.getLibraryName());
                DomainFile extFile = script.parseDomainFile(extPath);
                ProgramManager pman = script.getState().getTool().getService(ProgramManager.class);
                Program extProg = pman.openCachedProgram(extFile, this);
                Address extAddr = extRef.getExternalLocation().getAddress();
                Symbol[] syms = extProg.getSymbolTable().getSymbols(extAddr);
                for (Symbol sym : syms) {
                    String extName = sym.getName();
                    String rttiType = classifySymbolName(extName);
                    if (rttiType == null) {
                        continue;
                    }
                    if (!cxxabiVtableAddrs.computeIfAbsent(extProg.getName(),
                            s -> new HashMap<>()).containsKey(extAddr)) {
                        cxxabiVtableAddrs.get(extProg.getName()).put(extAddr, rttiType);
                    }
                }
                extProg.release(this);
            }
        }
    }

    /**
     * Check if a symbol name refers to the *vtable* of a __cxxabiv1 typeinfo class.
     * Returns the base type name or null.
     * <p>
     * Only vtable symbols may qualify: the typeinfo struct (_ZTI...) and the typeinfo
     * name string (_ZTS...) of the same class carry the class name too, and accepting
     * those makes unrelated words (e.g. a __base_type field pointing at another module's
     * _ZTI symbol) look like typeinfo vptrs.
     */
    private String classifySymbolName(String name) {
        if (name == null) return null;
        if (!isVtableSymbolName(name)) return null;
        return classifyCxxabiClassName(name);
    }

    /**
     * Match the __cxxabiv1 typeinfo class name inside a symbol name, ignoring what kind
     * of symbol it is. Returns the base type name or null.
     */
    private String classifyCxxabiClassName(String name) {
        if (name == null) return null;
        // Order matters: check __vmi first, then __si, then __class
        // to avoid false matches (e.g. "__class" matching inside "__si_class")
        if (name.contains("__vmi_class_type_info")) return "__vmi_class_type_info";
        if (name.contains("__si_class_type_info")) return "__si_class_type_info";
        if (name.contains("__class_type_info")) return "__class_type_info";

        return null;
    }

    /** True if the symbol name denotes a vtable rather than a typeinfo struct or name string. */
    private boolean isVtableSymbolName(String name) {
        // _ZTI = typeinfo struct, _ZTS = typeinfo name string, and Ghidra's demangled
        // forms of those end in "typeinfo" / "typeinfo-name".
        if (name.startsWith("_ZTI") || name.startsWith("_ZTS")) return false;
        int sep = name.lastIndexOf("::");
        String last = (sep < 0) ? name : name.substring(sep + 2);
        if (last.equals("typeinfo") || last.equals("typeinfo-name")) return false;

        // _ZTV = vtable; "vtable" also covers the demangled form and the
        // "X_vtable" / "X::vtable" labels created by scanForTypeInfoRefs.
        return name.startsWith("_ZTV") || name.contains("vtable");
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

        AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
        // Scan every 4-byte-aligned address for values matching __cxxabiv1 vtable addresses
        for (long off = startOff; off + PTR_SIZE <= endOff + 1; off += PTR_SIZE) {
            Address addr = start.getNewAddress(off);

            long value = Integer.toUnsignedLong(mem.getInt(addr));
            Address toCheck = addressSpace.getAddress(value);
            String rttiType = cxxabiVtableAddrs.computeIfAbsent(program.getName(),
                    s -> new HashMap<>()).get(toCheck);
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
                // Check label name
                String label = extRef.getLabel();
                String rttiType = classifySymbolName(label);
                if (rttiType != null) return rttiType;

                // Check if target address matches a known __cxxabiv1 vtable address
                Address extAddr = extRef.getExternalLocation().getAddress();
                String extName = extRef.getLibraryName();
                if (extName.equals("|static|")) extName = script.getCurrentProgram().getName();
                if (extAddr != null) {
                    rttiType = cxxabiVtableAddrs.computeIfAbsent(extName,
                            s -> new HashMap<>()).get(extAddr);
                    if (rttiType != null) return rttiType;
                }
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

        // Typeinfo candidates whose __name is not a mangled type name: false positives
        // from the .rodata scan. Collected here and dropped after the loop.
        List<Long> bogus = new ArrayList<>();

        for (Map.Entry<Long, String> entry : discoveredTypeinfos.entrySet()) {
            long tiAddr = entry.getKey();
            Address structAddr = space.getAddress(tiAddr);

            // Read __name pointer at offset 4
            long namePtr;
            Address nameAddr;
            try {
                namePtr = Integer.toUnsignedLong(mem.getInt(structAddr.add(PTR_SIZE)));
                nameAddr = space.getAddress(namePtr);
            } catch (Exception e) {
                script.printf("ERROR demangling: key = %08x ; value = %s\n", tiAddr, entry.getValue());
                throw e;
            }

            if (!mem.getLoadedAndInitializedAddressSet().contains(nameAddr)) {
                script.printf("    WARNING: typeinfo at 0x%08x has __name -> 0x%s " +
                        "(not initialized memory); dropping as false positive\n", tiAddr, nameAddr);
                bogus.add(tiAddr);
                continue;
            }
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
                            nameAddr);
                    continue;
                }
            }

            SymbolTable symTab = program.getSymbolTable();
            if (data != null && data.getValue() instanceof String name) {
                if (!isPlausibleMangledTypeName(name)) {
                    script.printf("    WARNING: typeinfo at 0x%08x has __name -> 0x%s " +
                            "which is not a mangled type name (%s); " +
                            "dropping as false positive\n", tiAddr, nameAddr, describe(name));
                    bogus.add(tiAddr);
                    continue;
                }
                // Set symbol name with _ZTS prefix for demangling
                String mangled = "_ZTS" + name;
                try {
                    // Reuse the mangled symbol if it is already here (earlier run), otherwise
                    // add it. Never rename an arbitrary existing symbol: on a re-run syms[0]
                    // may well be the demangled label from last time.
                    Symbol mangledSym = null;
                    for (Symbol sym : symTab.getSymbols(nameAddr)) {
                        if (sym.getName().equals(mangled)) {
                            mangledSym = sym;
                            break;
                        }
                    }
                    if (mangledSym == null) {
                        mangledSym = symTable.createLabel(nameAddr, mangled, SourceType.USER_DEFINED);
                    }
                    mangledSym.setPrimary();

                    DemangleAndNameNamespace(program, nameAddr, script.getMonitor(),false, true);

                    // The demangled label is added alongside; make sure the mangled name
                    // is still the primary symbol afterwards.
                    if (!mangledSym.isPrimary()) {
                        mangledSym.setPrimary();
                    }
                } catch (InvalidInputException e) {
                    // Never let one bad candidate abort a multi-module run
                    script.println("    WARNING: could not name typeinfo string: typeinfoAddr = 0x" +
                            structAddr + " nameAddr = 0x" + nameAddr +
                            " mangled = " + mangled + " : " + e.getMessage());
                    bogus.add(tiAddr);
                } catch (Exception e) {
                    script.println("ERROR demangling: typeinfoAddr = 0x" + structAddr +
                            " nameAddr = 0x" + nameAddr +
                            " mangled = " + mangled);
                    throw e;
                }
            }
        }

        for (long tiAddr : bogus) {
            discoveredTypeinfos.remove(tiAddr);
        }
        if (!bogus.isEmpty()) {
            script.printf("    Dropped %d false-positive typeinfo candidate(s)\n", bogus.size());
        }
    }

    /**
     * True if the string looks like an Itanium mangled type name, i.e. something that
     * can legally follow the _ZTS prefix and be accepted by SymbolUtilities.validateName.
     */
    private boolean isPlausibleMangledTypeName(String name) {
        if (name == null || name.isEmpty() || name.length() > 512) return false;
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '_' || c == '$' || c == '.';
            if (!ok) return false;
        }
        return true;
    }

    /** Printable rendering of a possibly-garbage string, for warnings. */
    private String describe(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length() && i < 16; i++) {
            char c = s.charAt(i);
            if (c >= 0x20 && c < 0x7f) sb.append(c);
            else sb.append(String.format("\\x%02x", (int) c & 0xff));
        }
        return sb.toString();
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
//                    script.printf("    __vmi base_count = %d at 0x%08x\n", baseCount, entry.getKey());
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