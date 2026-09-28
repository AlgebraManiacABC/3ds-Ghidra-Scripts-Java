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

    // The same names the other way round, so a discovered cxxabi class can be spelled
    // back into the _ZTV / _ZTI labels that go on its vtable head and typeinfo struct.
    private static final Map<String, String> CXXABI_TYPE_NAMES = new HashMap<>();
    static {
        for (Map.Entry<String, String> entry : CXXABI_MANGLED_NAMES.entrySet()) {
            CXXABI_TYPE_NAMES.put(entry.getValue(), entry.getKey());
        }
    }

    private Map<Address, String> scanForTypeInfoRefs(Program program) throws Exception {
        Map<Address, String> refs = new HashMap<>();
        Memory mem = program.getMemory();
        List<MemoryBlock> roBlocks = readOnlyBlocks(program);
        if (roBlocks.isEmpty()) {
            script.printerr("Could not find any read-only data block!");
            return null;
        }

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
            for (MemoryBlock block : roBlocks) {
              Address endOff = block.getEnd();
              for (Address off = block.getStart();
                   off.add(PTR_SIZE).compareTo(endOff) <= 0; off = off.add(PTR_SIZE)) {
                long here = mem.getInt(off);
                if (here != namePtr) continue;
                // Otherwise, this is a reference to the typeinfo-name.
                typeinfoStructAddrs.put(off.subtract(4), base.getValue());
                // The struct is this cxxabi class's own typeinfo: _ZTI names it
                String typeName = CXXABI_TYPE_NAMES.get(base.getValue());
                if (typeName != null) {
                    MangledNames.addMangled(script, program, off.subtract(4),
                            "_ZTI" + typeName);
                }
              }
            }
        }

        // Final pass: get references to the typeinfo structs, excluding inside the cxxabi structs
        SymbolTable symTab = program.getSymbolTable();
        for (Map.Entry<Address,String> entry : typeinfoStructAddrs.entrySet()) {
            long tiPtr = entry.getKey().getOffset();
            for (MemoryBlock block : roBlocks) {
              Address endOff = block.getEnd();
              for (Address off = block.getStart();
                   off.add(PTR_SIZE).compareTo(endOff) <= 0; off = off.add(PTR_SIZE)) {
                long here = mem.getInt(off);
                if (here != tiPtr) continue;
                // Otherwise, this is a reference to the typeinfo struct!
                if (!isInsideTypeInfoBase(off, typeinfoStructAddrs)) {
                    // A typeinfo's vptr stores vtable+8 (the first virtual function slot),
                    // which is off+4 here. off itself (vtable+4, the vtable's own typeinfo
                    // slot) is never stored anywhere, so registering it only adds noise.
                    refs.put(off.add(4), entry.getValue());
                    // Two labels, two conventions: the namespaced "vtable" marks the
                    // head (the _ZTV address, where the vtable struct starts), while the
                    // flat "X_vtable" marks the address point, which is the value
                    // scanForTypeinfoStructs matches against typeinfo vptr words.
                    symTab.createLabel(off.add(4),entry.getValue() + "_vtable", SourceType.USER_DEFINED);
                    symTab.createLabel(off.subtract(4),entry.getValue() + "::vtable", SourceType.USER_DEFINED);
                    // ...and the head's mangled spelling, beside the "::vtable" label
                    String typeName = CXXABI_TYPE_NAMES.get(entry.getValue());
                    if (typeName != null) {
                        MangledNames.addMangled(script, program, off.subtract(4),
                                "_ZTV" + typeName);
                    }
                }
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

        // Nothing above works on a module whose __cxxabiv1 name strings are absent -- a
        // .cro that inherits them from code.bin, or a build that dropped them. Structure
        // alone still gives them up.
        frequencyScanForAbiVtables(program);

        // Search external references. With a tool the modules come from its ProgramManager;
        // headless they are opened from the project directly (Programs.open).
        ProgramManager pman = Programs.manager(script);

        ReferenceManager refMan = program.getReferenceManager();
        ReferenceIterator refIter = refMan.getExternalReferences();
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (ref instanceof ExternalReference extRef) {
                ExternalManager extMan = program.getExternalManager();
                String extPath = extMan.getExternalLibraryPath(extRef.getLibraryName());
                DomainFile extFile = script.parseDomainFile(extPath);
                Program extProg;
                try {
                    extProg = Programs.open(extFile, this, pman, script.getMonitor());
                } catch (Exception e) {
                    continue;
                }
                if (extProg == null) continue;
                // Held as a consumer until released, so anything thrown in between leaves
                // the module pinned open for the rest of the session.
                try {
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
                } finally {
                    extProg.release(this);
                }
            }
        }
    }

    // ---------------------------------------------------------------
    //  Step 1b: Find them again, from structure alone
    // ---------------------------------------------------------------

    /** Below this many sharers a candidate is tail noise, not an ABI vtable. */
    private static final int MIN_ABI_VTABLE_USERS = 16;

    /** Largest {@code __vmi_class_type_info::__base_count} treated as plausible. */
    private static final int MAX_PLAUSIBLE_BASE_COUNT = 64;

    /**
     * The three {@code __cxxabiv1} typeinfo vtables, found without a single symbol or
     * name string.
     *
     * <p>Every typeinfo structure begins with a pointer to one of exactly three shared ABI
     * vtables, followed by a pointer to its {@code _ZTS} name string. Nothing else in an
     * image repeats that shape -- two consecutive read-only pointers, the first one shared
     * -- thousands of times over, so counting the first words across read-only data lifts
     * the three clear of a long tail of ordinary data.
     *
     * <p>Telling the three apart then needs no names either. A {@code __si_class_type_info}
     * structure is 12 bytes and its word 2 is the one base's typeinfo, so nearly every
     * user of the {@code __si} vtable has a word 2 that is itself a typeinfo -- that is the
     * discriminator, and it is decisive (2220 of 2225 on the measured image). Of the other
     * two, {@code __vmi} users carry a small flags word at word 2 and a small base count at
     * word 3, each followed by that many resolvable base entries; {@code __class} users are
     * 8 bytes and have nothing dependable there at all.
     *
     * <p>Only runs when the name-string and symbol routes have not already produced all
     * three, and never overwrites what they found.
     */
    private void frequencyScanForAbiVtables(Program program) {
        Map<Address, String> known = cxxabiVtableAddrs.computeIfAbsent(
                program.getName(), s -> new HashMap<>());
        if (new HashSet<>(known.values()).size() >= 3) return;

        List<MemoryBlock> roBlocks = readOnlyBlocks(program);
        if (roBlocks.isEmpty()) return;
        RoImage ro = new RoImage(roBlocks, program.getMemory().isBigEndian());

        // Pass 1: count. Two passes rather than one so the user lists, which are only
        // wanted for three values, never have to be held for every value in the image.
        Map<Long, Integer> counts = new HashMap<>();
        for (MemoryBlock block : roBlocks) {
            long start = block.getStart().getOffset();
            long end = block.getEnd().getOffset();
            for (long p = start; p + 2L * PTR_SIZE <= end + 1; p += PTR_SIZE) {
                Long v = ro.wordAt(p);
                if (v == null || !ro.contains(v)) continue;
                Long next = ro.wordAt(p + PTR_SIZE);
                if (next == null || !ro.contains(next)) continue;
                counts.merge(v, 1, Integer::sum);
            }
        }

        List<Map.Entry<Long, Integer>> ranked = new ArrayList<>(counts.entrySet());
        ranked.sort((a, b) -> Integer.compare(b.getValue(), a.getValue()));

        script.println("    Frequency scan for __cxxabiv1 vtables -- most-shared first " +
                "words in read-only data:");
        for (int i = 0; i < Math.min(5, ranked.size()); i++) {
            script.println(String.format("      0x%08x  shared by %d structures%s",
                    ranked.get(i).getKey(), ranked.get(i).getValue(),
                    i == 3 ? "   <- tail begins here if the scan worked" : ""));
        }
        if (ranked.size() < 3 || ranked.get(2).getValue() < MIN_ABI_VTABLE_USERS) {
            script.println("    ...no three candidates stand out; leaving the __cxxabiv1 " +
                    "vtables unresolved for this module");
            return;
        }

        List<Long> candidates = List.of(ranked.get(0).getKey(), ranked.get(1).getKey(),
                ranked.get(2).getKey());
        Set<Long> candidateSet = new HashSet<>(candidates);

        // Pass 2: gather the users of just those three and score each candidate.
        Map<Long, List<Long>> users = new HashMap<>();
        for (MemoryBlock block : roBlocks) {
            long start = block.getStart().getOffset();
            long end = block.getEnd().getOffset();
            for (long p = start; p + 2L * PTR_SIZE <= end + 1; p += PTR_SIZE) {
                Long v = ro.wordAt(p);
                if (v == null || !candidateSet.contains(v)) continue;
                Long next = ro.wordAt(p + PTR_SIZE);
                if (next == null || !ro.contains(next)) continue;
                users.computeIfAbsent(v, k -> new ArrayList<>()).add(p);
            }
        }

        Map<Long, Double> siScore = new HashMap<>();
        Map<Long, Double> vmiScore = new HashMap<>();
        for (long c : candidates) {
            List<Long> us = users.getOrDefault(c, List.of());
            int si = 0, vmi = 0;
            for (long p : us) {
                if (pointsAtTypeinfo(ro, candidateSet, p + 2L * PTR_SIZE)) si++;
                if (readsAsVmiBody(ro, candidateSet, p)) vmi++;
            }
            siScore.put(c, us.isEmpty() ? 0.0 : (double) si / us.size());
            vmiScore.put(c, us.isEmpty() ? 0.0 : (double) vmi / us.size());
        }

        // The __si vtable is the one whose users overwhelmingly name a base; of what is
        // left, the __vmi vtable is the one whose users read as flags + base array.
        long si = candidates.stream().max(Comparator.comparingDouble(siScore::get)).orElseThrow();
        List<Long> rest = new ArrayList<>(candidates);
        rest.remove(si);
        long vmi = rest.stream().max(Comparator.comparingDouble(vmiScore::get)).orElseThrow();
        rest.remove(vmi);
        long plain = rest.get(0);

        // Frequency alone is not enough: a module with no RTTI of its own still has shared
        // words, e.g. a table of string pointers (HugeBattle.cro in MLDT, whose top three
        // were odd addresses scoring 0% on both tests). A real ABI vtable is word-aligned,
        // and its __si users overwhelmingly name a base.
        boolean aligned = candidates.stream().allMatch(c -> c % PTR_SIZE == 0);
        if (!aligned || siScore.get(si) < 0.5) {
            script.println(String.format("    ...top candidates are not typeinfo vtables " +
                    "(%s, best base-naming %.0f%%); leaving the __cxxabiv1 vtables unresolved " +
                    "for this module", aligned ? "aligned" : "misaligned",
                    100 * siScore.get(si)));
            return;
        }

        Map<Long, String> roles = new LinkedHashMap<>();
        roles.put(plain, "__class_type_info");
        roles.put(si, "__si_class_type_info");
        roles.put(vmi, "__vmi_class_type_info");

        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        Set<String> takenRoles = new HashSet<>(known.values());
        for (Map.Entry<Long, String> e : roles.entrySet()) {
            Address addr = space.getAddress(e.getKey());
            script.println(String.format("      0x%08x -> %-22s (base-naming %.0f%%, " +
                            "vmi-shaped %.0f%%, %d users)",
                    e.getKey(), e.getValue(), 100 * siScore.get(e.getKey()),
                    100 * vmiScore.get(e.getKey()),
                    users.getOrDefault(e.getKey(), List.of()).size()));
            if (known.containsKey(addr) || takenRoles.contains(e.getValue())) continue;
            known.put(addr, e.getValue());
            takenRoles.add(e.getValue());
        }
    }

    /** True when the word at {@code at} points at a structure headed by an ABI vtable. */
    private boolean pointsAtTypeinfo(RoImage ro, Set<Long> abiVtables, long at) {
        Long ptr = ro.wordAt(at);
        if (ptr == null) return false;
        Long head = ro.wordAt(ptr);
        return head != null && abiVtables.contains(head);
    }

    /**
     * True when the structure at {@code p} reads as a {@code __vmi_class_type_info}: a
     * small flags word, a small base count, and that many resolvable base entries.
     */
    private boolean readsAsVmiBody(RoImage ro, Set<Long> abiVtables, long p) {
        Long flags = ro.wordAt(p + 2L * PTR_SIZE);
        Long count = ro.wordAt(p + 3L * PTR_SIZE);
        if (flags == null || count == null) return false;
        if (flags > 3) return false;                       // only bits 0 and 1 are defined
        if (count < 1 || count > MAX_PLAUSIBLE_BASE_COUNT) return false;
        for (long i = 0; i < count; i++) {
            if (!pointsAtTypeinfo(ro, abiVtables, p + 4L * PTR_SIZE + 8 * i)) return false;
        }
        return true;
    }

    /**
     * The read-only blocks held as bytes, so a whole-image sweep costs one read per block
     * instead of two million calls into {@link Memory}.
     */
    private static final class RoImage {
        private final long[] starts;
        private final byte[][] bytes;
        private final boolean bigEndian;

        RoImage(List<MemoryBlock> blocks, boolean bigEndian) {
            this.bigEndian = bigEndian;
            List<Long> s = new ArrayList<>();
            List<byte[]> b = new ArrayList<>();
            for (MemoryBlock block : blocks) {
                try {
                    int size = (int) Math.min(block.getSize(), Integer.MAX_VALUE);
                    byte[] buf = new byte[size];
                    int read = block.getBytes(block.getStart(), buf);
                    if (read <= 0) continue;
                    s.add(block.getStart().getOffset());
                    b.add(read == size ? buf : Arrays.copyOf(buf, read));
                } catch (Exception e) {
                    // An unreadable block contributes nothing; the others still count.
                }
            }
            starts = new long[s.size()];
            for (int i = 0; i < s.size(); i++) starts[i] = s.get(i);
            bytes = b.toArray(new byte[0][]);
        }

        /** True when a whole word can be read at {@code addr}. */
        boolean contains(long addr) {
            return blockOf(addr) >= 0;
        }

        /** The word at {@code addr}, unsigned, or null when it is not inside a block. */
        Long wordAt(long addr) {
            int i = blockOf(addr);
            if (i < 0) return null;
            int o = (int) (addr - starts[i]);
            byte[] buf = bytes[i];
            int v = bigEndian
                    ? ((buf[o] & 0xff) << 24) | ((buf[o + 1] & 0xff) << 16)
                            | ((buf[o + 2] & 0xff) << 8) | (buf[o + 3] & 0xff)
                    : (buf[o] & 0xff) | ((buf[o + 1] & 0xff) << 8)
                            | ((buf[o + 2] & 0xff) << 16) | ((buf[o + 3] & 0xff) << 24);
            return Integer.toUnsignedLong(v);
        }

        private int blockOf(long addr) {
            for (int i = 0; i < starts.length; i++) {
                if (addr >= starts[i] && addr + PTR_SIZE <= starts[i] + bytes[i].length) {
                    return i;
                }
            }
            return -1;
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
        // _ZTT = VTT; _ZT_C1_ / _ZT_B1_ are ARMCC's construction-vtable forms and _ZTC is
        // Itanium's spelling for the same thing. None of these is a
        // __cxxabiv1 class's vtable, and letting one through would have its address
        // scanned for as though every word pointing at it were a typeinfo struct.
        if (name.startsWith("_ZTT") || name.startsWith("_ZTC")
                || name.startsWith("_ZT_C1_") || name.startsWith("_ZT_B1_")) {
            return false;
        }
        int sep = name.lastIndexOf("::");
        String last = (sep < 0) ? name : name.substring(sep + 2);
        if (last.equals("typeinfo") || last.equals("typeinfo-name")) return false;
        // The VTT label this pipeline writes sits in a class namespace as "VTT"; it is
        // deliberately not spelled with "vtable" in it, but reject it explicitly too.
        if (last.equals("VTT")) return false;

        // _ZTV = vtable; "vtable" also covers the demangled form and the
        // "X_vtable" / "X::vtable" labels created by scanForTypeInfoRefs.
        return name.startsWith("_ZTV") || name.contains("vtable");
    }

    // ---------------------------------------------------------------
    //  Step 2: Scan .rodata for typeinfo structs
    // ---------------------------------------------------------------

    private void scanForTypeinfoStructs(Program program) throws Exception {
        Memory mem = program.getMemory();
        List<MemoryBlock> roBlocks = readOnlyBlocks(program);
        if (roBlocks.isEmpty()) {
            script.printerr("Could not find any read-only data block!");
            return;
        }

        AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
        // Scan every 4-byte-aligned address for values matching __cxxabiv1 vtable addresses
        for (MemoryBlock block : roBlocks) {
          Address start = block.getStart();
          long startOff = start.getOffset();
          long endOff = block.getEnd().getOffset();
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

    /**
     * Every block that may hold typeinfo, vtables or name strings.
     *
     * <p>Typeinfo discovery is a sweep of every word-aligned read-only address, so it has
     * to see <em>all</em> of them: an image with its const data split across several
     * blocks would otherwise have whole subtrees of the class graph silently missing.
     * Returning the first {@code .rodata} block, as this used to, was that bug.
     *
     * <p>The fallback deliberately does not test {@code isWrite()}. On 3DS images the
     * const data is frequently mapped writable -- {@code .rodata} on ACNL is -- so a
     * writability test rejects exactly the block being looked for. {@code isInitialized()}
     * is the test that matters, since an uninitialized block has no bytes to read.
     *
     * <p>Kept identical to {@link VtableScan}'s own block selection on purpose: the two
     * sweeps have to agree on where const data is, or a vtable is found in a block whose
     * typeinfo was never discovered.
     */
    private List<MemoryBlock> readOnlyBlocks(Program program) {
        List<MemoryBlock> blocks = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            String name = block.getName();
            if (name.equals(".rodata") || name.equals("rodata")) {
                blocks.add(block);
            }
        }
        if (!blocks.isEmpty()) return blocks;
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (block.isInitialized() && block.isRead() && !block.isExecute()) {
                blocks.add(block);
            }
        }
        return blocks;
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

            // Determine max base count needed. A __vmi candidate whose flags or base count
            // is out of range is not a __vmi_class_type_info: sizing a struct from its
            // count would lay millions of bytes of array over the image.
            Set<Integer> baseCounts = new HashSet<>();
            Memory mem = program.getMemory();
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            List<Long> badVmi = new ArrayList<>();
            int vmiTotal = 0;
            for (Map.Entry<Long, String> entry : discoveredTypeinfos.entrySet()) {
                if (entry.getValue().equals("__vmi_class_type_info")) {
                    vmiTotal++;
                    Address addr = space.getAddress(entry.getKey());
                    int flags = mem.getInt(addr.add(8));
                    int baseCount = mem.getInt(addr.add(12));
                    if (flags < 0 || flags > 3
                            || baseCount < 1 || baseCount > MAX_PLAUSIBLE_BASE_COUNT) {
                        script.printf("    WARNING: __vmi typeinfo at 0x%08x has flags 0x%x, " +
                                "base count %d; dropping as false positive\n",
                                entry.getKey(), flags, baseCount);
                        badVmi.add(entry.getKey());
                        continue;
                    }
                    baseCounts.add(baseCount);
                }
            }
            for (long tiAddr : badVmi) {
                discoveredTypeinfos.remove(tiAddr);
            }
            // Many failures at once means the __vmi vtable itself is misidentified (most
            // likely swapped with __class, whose 8-byte structs leave word 3 as whatever
            // follows), not that a few candidates are noise.
            if (vmiTotal > 0 && badVmi.size() * 4 > vmiTotal) {
                script.printerr(String.format("RTTI: %d of %d __vmi typeinfo candidates in %s " +
                        "failed the flags/base-count check -- the __cxxabiv1 vtable roles are " +
                        "probably misassigned for this module", badVmi.size(), vmiTotal,
                        program.getName()));
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
                // The mangled spelling goes beside it, whether or not the label is new,
                // so a re-run backfills programs processed before this existed. The _ZTS
                // string at __name is the compiler's own, so no re-mangling is needed.
                String enc = MangledNames.typeNameFromNameString(program, namePtrAddr);
                if (enc != null) {
                    MangledNames.addMangled(script, program, addr, "_ZTI" + enc);
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
        List<MemoryBlock> roBlocks = readOnlyBlocks(program);
        if (roBlocks.isEmpty()) {
            script.printerr("Could not find any read-only data block!");
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

        for (MemoryBlock block : roBlocks) {
          Address start = block.getStart();
          long startOff = start.getOffset();
          long endOff = block.getEnd().getOffset();
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
}