// Shared, read-only vtable discovery for ARMCC 4.1 images.
//
// The rename pipeline used to treat a single RTTI slot as its unit of work and infer
// everything else by fixed arithmetic (head = slot-4, point = slot+4) plus address-order
// sequencing ("the first table seen for this typeinfo is the primary"). ARMCC's real unit
// is a *vtable group*: a contiguous run of sub-tables under one _ZTV, each with a
// variable-length header, optionally accompanied by an adjacent VTT.
//
// Two facts break the old model:
//
//   1. A class with virtual bases prepends one vbase-offset word per virtual base IN FRONT
//      of offset-to-top, so the head moves but the address point does not. The only fixed
//      relationships are offset-to-top at rttiSlot-4 and the address point at rttiSlot+4.
//
//   2. A table carrying class X's typeinfo is not necessarily X's vtable. ARMCC emits
//      *construction vtables* -- _ZT_C1_<Base><Derived> / _ZT_B1_<VBase><n>_<Base><Derived>
//      -- in plain .constdata, carrying the base's typeinfo, one per deriving class, and
//      possibly hundreds of KB away. They are reachable only through a VTT, which is what
//      tells them apart from the real thing -- not the literal-load test vtables.md
//      proposes, which measurement shows is unavailable on these images. See the note
//      above classifyGroups().
//
// This class produces groups rather than loose slots, classifies each one, and attributes
// construction vtables to the class they were emitted for. It writes nothing to the
// program, so the export script, the diagnostic script and the rename pipeline can all
// share one implementation.
//
// @category RTTI
// @author AlgebraManiacABC

package util;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

import java.util.*;
import java.util.function.Consumer;

public final class VtableScan {

    private static final int PTR_SIZE = 4;

    /** A vbase-offset word this far from zero is not plausibly one. */
    private static final int MAX_VBASE_OFFSET = 0x10000;

    /** Most vbase-offset words we will accept in front of one sub-table's offset-to-top. */
    private static final int MAX_VBASE_WORDS = 16;

    /**
     * Largest believable offset-to-top: a displacement inside one object, not an address.
     *
     * <p>64 KB. A megabyte, tried first, was too generous to do the job: the two
     * {@code sead::FixedSafeString<32>} false groups carry 854,016, which is under it, so
     * they survived. The largest real one measured here is 8,508
     * ({@code state::Mode<LetterDragItemWindow>}), so this still clears it sevenfold.
     */
    private static final long MAX_OFFSET_TO_TOP = 1L << 16;

    /** Alignment slack tolerated between one sub-table's end and the next one's head. */
    private static final int CHAIN_SLACK_WORDS = 1;

    /** Shortest run of address-point-valued words we will call a VTT. */
    private static final int MIN_VTT_ENTRIES = 2;

    /** Bytes compared when reporting that a construction table copies a real one. */
    private static final int LEADING_IDENTITY_BYTES = 168;

    // ---------------------------------------------------------------
    //  Result types
    // ---------------------------------------------------------------

    /**
     * One sub-table: an optional run of header words, then offset-to-top, then the
     * typeinfo pointer, then the function slots.
     *
     * <p>The header run is one of two things, told apart by {@link #hasVcallOffsets()}:
     * <b>vbase offsets</b> on a table that starts a complete object, one per virtual base;
     * or <b>vcall offsets</b> on a table describing a virtual base subobject, one per
     * virtual function of that base with the destructor pair sharing one. The fields are
     * spelled {@code vbase*} for both because the vbase case came first; the accessor is
     * what to test.
     */
    public record SubTable(
            Address head,             // rttiSlot - 4*(1 + vbaseCount)
            Address offsetToTopAddr,  // rttiSlot - 4, always
            Address rttiSlot,
            Address addressPoint,     // rttiSlot + 4, always
            int offsetToTop,
            int vbaseCount,           // total header words: vbaseWords + the vcall run
            int vbaseWords,           // how many of them, outermost, are vbase offsets
            int[] vbaseOffsets,       // vbaseCount words, in memory order
            long typeinfo,
            List<Long> slots) {

        /**
         * True when any of the header run is vcall offsets. A header is not one thing or
         * the other: armcc's order is {@code [vbase offsets][vcall offsets]} with the vbase
         * offsets outermost (open answers Q2), and the {@code nn::fs} tables carry both --
         * one vbase word, then nine vcall words. Calling the whole run "vbase" was wrong
         * for every B table and for those mixed headers alike.
         */
        public boolean hasVcallOffsets() {
            return vbaseCount > vbaseWords;
        }

        /** vbase, vcall, vbase+vcall or none, for the export's header_kind column. */
        public String headerKind() {
            if (vbaseCount == 0) return "none";
            if (vbaseWords == 0) return "vcall";
            if (vbaseWords == vbaseCount) return "vbase";
            return "vbase+vcall";
        }

        /**
         * What header word {@code i} (in memory order) is for. The vbase offsets come
         * first; the vcall run after them grows outward from offset-to-top, so the word
         * immediately before offset-to-top is the destructor's, shared by the D1/D0 pair.
         */
        public String headerWordName(int i) {
            if (i < vbaseWords) return "vbase_offset_" + i;
            int vcalls = vbaseCount - vbaseWords;
            int k = i - vbaseWords;
            return (k == vcalls - 1) ? "vcall_dtor" : "vcall_slot" + (vcalls - k);
        }

        /** First address past the last function slot. */
        public Address end() {
            return addressPoint.add((long) PTR_SIZE * slots.size());
        }

        /** Total bytes from the head to the end of the last slot. */
        public int length() {
            return PTR_SIZE * (vbaseCount + 2 + slots.size());
        }

        /** A primary sub-table starts a group; secondaries carry a negative offset-to-top. */
        public boolean isPrimary() {
            return offsetToTop == 0;
        }
    }

    /**
     * How a group's address point is reached, which is what says whether the group is the
     * class's own vtable.
     */
    public enum Kind {
        /** The class's own vtable: named by its VTT's entry 0, or reached by no VTT. */
        REAL,
        /** Ambiguous, but the best candidate the class has. */
        REAL_WEAK,
        /** Reached from another class's VTT: emitted for that class's constructor. */
        CONSTRUCTION,
        /** Malformed, or reached from nowhere at all. */
        ORPHAN
    }

    /** A contiguous run of sub-tables under one _ZTV symbol. */
    public static final class VtableGroup {
        private final String className;
        private final List<SubTable> subs;
        private Kind kind = Kind.ORPHAN;
        private String derivedOwner;
        private Vtt vtt;
        private final List<String> evidence = new ArrayList<>();

        VtableGroup(String className, List<SubTable> subs) {
            this.className = className;
            this.subs = List.copyOf(subs);
        }

        /** The class named by the typeinfo every sub-table repeats. */
        public String className() { return className; }

        public List<SubTable> subs() { return subs; }

        public SubTable primary() { return subs.get(0); }

        public Address head() { return subs.get(0).head(); }

        public Address addressPoint() { return subs.get(0).addressPoint(); }

        public Kind kind() { return kind; }

        /**
         * For a construction vtable, the class whose constructor uses it; {@code null}
         * when attribution failed or the group is not a construction vtable.
         */
        public String derivedOwner() { return derivedOwner; }

        /** The VTT adjacent to this group, when this group owns one. */
        public Vtt vtt() { return vtt; }

        public String evidence() { return String.join("; ", evidence); }

        public boolean isReal() { return kind == Kind.REAL || kind == Kind.REAL_WEAK; }

        void setKind(Kind k) { this.kind = k; }
        void setDerivedOwner(String d) { this.derivedOwner = d; }
        void setVtt(Vtt v) { this.vtt = v; }
        void note(String s) { evidence.add(s); }
    }

    /** A flat array of pointers to address points, used while constructing an object. */
    public record Vtt(Address start, int length, String ownerClass, List<Address> entries) {
        public Address end() {
            return start.add((long) PTR_SIZE * entries.size());
        }
    }

    // ---------------------------------------------------------------
    //  Inputs
    // ---------------------------------------------------------------

    private final Program program;
    private final Map<Long, String> typeinfoToClassName;
    private final Map<Long, Integer> typeinfoSizes;
    private final Map<String, List<BaseRef>> baseInfo;
    private final Consumer<String> log;
    private final TaskMonitor monitor;

    private final AddressSpace space;
    private final Memory memory;
    private final boolean bigEndian;

    // ---------------------------------------------------------------
    //  Outputs
    // ---------------------------------------------------------------

    private final List<VtableGroup> groups = new ArrayList<>();
    private final List<Vtt> vtts = new ArrayList<>();

    /** Address point offset -> the group it belongs to. */
    private final Map<Long, VtableGroup> groupByPoint = new HashMap<>();

    /** Group head offset -> the group starting there. */
    private final Map<Long, VtableGroup> groupByHead = new HashMap<>();

    /** Address point offset -> the sub-table that starts there. */
    private final Map<Long, SubTable> subByPoint = new HashMap<>();

    /** Address-point value -> every address in the image holding that value. */
    private final Map<Long, List<Address>> occurrences = new HashMap<>();

    /** Addresses that fall inside a detected VTT run. */
    private final Set<Long> vttWordAddrs = new HashSet<>();

    private final Map<String, Integer> expectedVbaseCache = new HashMap<>();

    // Counters worth printing after a scan.
    private int chainSlackUsed;
    private int slotsRejected;
    private int rejectedAlign;
    private int rejectedMode;
    private int rejectedOffsetToTop;
    private int headerGapsClosed;
    private final List<String> headerGapNotes = new ArrayList<>();
    private int positiveOffsetToTop;
    private int noOwnVtable;
    private int ctorPairsAgreed;
    private int ctorPairsMismatched;
    private int vbaseValidationFailures;
    private int promotedWeak;
    private int demotedExtraReal;
    private int attributedByVtt;
    private int attributedByOffset;
    private int unattributedConstruction;

    /**
     * @param program              the program to scan
     * @param typeinfoToClassName  typeinfo struct address -> class name
     * @param typeinfoSizes        typeinfo struct address -> applied struct size
     * @param baseInfo             class name -> direct bases; may be empty, in which case
     *                             virtual-base headers on a group's first sub-table cannot
     *                             be predicted and are assumed absent
     * @param log                  where to print diagnostics, e.g. {@code script::println}
     * @param monitor              cancellation monitor, or {@code null}
     */
    public VtableScan(Program program,
                      Map<Long, String> typeinfoToClassName,
                      Map<Long, Integer> typeinfoSizes,
                      Map<String, List<BaseRef>> baseInfo,
                      Consumer<String> log,
                      TaskMonitor monitor) {
        this.program = program;
        this.typeinfoToClassName = typeinfoToClassName;
        this.typeinfoSizes = (typeinfoSizes != null) ? typeinfoSizes : Map.of();
        this.baseInfo = (baseInfo != null) ? baseInfo : Map.of();
        this.log = (log != null) ? log : s -> { };
        this.monitor = monitor;
        this.space = program.getMinAddress().getAddressSpace();
        this.memory = program.getMemory();
        this.bigEndian = program.getLanguage().isBigEndian();
    }

    /**
     * Names the class of a typeinfo that a word *imports* from another module, or null.
     * In a CRO, a table built for a class that lives in code.bin carries that class's
     * typeinfo as an import: the word is 0 in memory with an import record, so the plain
     * value test never saw it. ModuleMusFish's construction tables for code.bin bases were
     * invisible that way, and the VTTs pointing into them broke into fragments -- 40 of
     * which were then named _ZTT16AcFishMuseumBase. Set before scan(); the default finds
     * nothing, which is the old behaviour.
     */
    private java.util.function.Function<Address, String> importedTypeinfo = a -> null;
    private final Map<Long, String> importedSlotClass = new HashMap<>();
    private int importedRttiSlots = 0;

    public void setImportedTypeinfoResolver(java.util.function.Function<Address, String> r) {
        if (r != null) importedTypeinfo = r;
    }

    /** A stand-in typeinfo value for an imported class: equal for equal classes, never an address. */
    private static long pseudoTypeinfo(String className) {
        return -1L - (className.hashCode() & 0x7fffffffL);
    }

    // ---------------------------------------------------------------
    //  Public API
    // ---------------------------------------------------------------

    /**
     * The order matters. Sizing a sub-table's header needs to know whether the sub-table
     * describes a virtual base -- a vcall-offset run is as long as that base's vtable --
     * and whether it is a separate object or a continuation of the one before it. Neither
     * can be read off the header's own bytes: a vcall run is mostly zeros, and a
     * construction vtable's virtual-base table has the same shape as a real vtable's
     * virtual-base sub-table, which does continue its group. The VTTs settle both, so the
     * word scan that finds them runs before anything is sized.
     */
    public void scan() throws Exception {
        List<Raw> raws = buildRawSubTables();
        scanMemoryWords(raws);
        indexRaws(raws);
        deriveHeadersFromContiguity(raws);
        chainGroups(raws);
        resolveVtts();
        classifyGroups();
        reconcilePerClass();
        crossCheckConstructionPairs();
    }

    /**
     * Check each construction pair against itself: the C table's vbase-offset word must be
     * the negative of the B table's offset-to-top.
     *
     * <p>The two tables describe the same relationship from opposite ends. The C table says
     * "the virtual base sits +N bytes into this object"; the B table describes that base's
     * subobject and says "the complete object starts -N bytes back from here". Measured on
     * {@code AcInsectCommon}: {@code 0x18C} against {@code -0x18C}.
     *
     * <p>Nothing is corrected from this -- it is an independent reading of a number that
     * was derived elsewhere, so a disagreement says one of the two headers is mis-sized
     * without saying which. It is reported rather than acted on, and it is the check that
     * should fire for the tables whose size does not match their row count.
     */
    /** True when the class declares a non-virtual base sitting at exactly this offset. */
    private boolean isNonVirtualBaseOffset(String className, int offset) {
        List<BaseRef> bases = baseInfo.get(className);
        if (bases == null) return false;
        for (BaseRef b : bases) {
            if (!b.isVirtual() && b.offset() == offset) return true;
        }
        return false;
    }

    private void crossCheckConstructionPairs() {
        Map<String, List<VtableGroup>> byOwner = new HashMap<>();
        for (VtableGroup group : groups) {
            if (group.kind() != Kind.CONSTRUCTION || group.derivedOwner() == null) continue;
            byOwner.computeIfAbsent(group.derivedOwner(), k -> new ArrayList<>()).add(group);
        }
        for (List<VtableGroup> owned : byOwner.values()) {
            for (VtableGroup b : owned) {
                if (b.primary().offsetToTop() >= 0) continue;
                int want = -b.primary().offsetToTop();
                // Only a B table describing a *virtual* base has a matching vbase-offset
                // word on the C table. A B table for a plain secondary base -- which armcc
                // does emit, e.g. _ZT_B1_19ResourceGetSkeletal1_... where
                // ResourceGetSkeletal sits at a nonvirtual +208 -- has nothing on the C
                // side to agree with, and reporting it as a mismatch says the data is
                // wrong when only the question was.
                if (isNonVirtualBaseOffset(b.className(), want)) continue;
                boolean matched = false;
                for (VtableGroup c : owned) {
                    if (c.primary().offsetToTop() != 0) continue;
                    for (int v : c.primary().vbaseOffsets()) {
                        if (v == want) { matched = true; break; }
                    }
                    if (matched) break;
                }
                if (matched) {
                    ctorPairsAgreed++;
                } else {
                    ctorPairsMismatched++;
                    b.note("no C table for " + b.derivedOwner() + " carries a vbase offset of "
                            + want + " to match this table's offset-to-top");
                }
            }
        }
    }

    public List<VtableGroup> groups() {
        return Collections.unmodifiableList(groups);
    }

    public List<Vtt> vtts() {
        return Collections.unmodifiableList(vtts);
    }

    /** The one group that is the class's own vtable, or {@code null} if it has none. */
    public VtableGroup realGroupFor(String className) {
        for (VtableGroup g : groups) {
            if (g.isReal() && className.equals(g.className())) return g;
        }
        return null;
    }

    /** Every class that has a REAL or REAL_WEAK group, in class-name order. */
    public Map<String, VtableGroup> realGroups() {
        Map<String, VtableGroup> out = new TreeMap<>();
        for (VtableGroup g : groups) {
            if (g.isReal()) out.putIfAbsent(g.className(), g);
        }
        return out;
    }

    public VtableGroup groupAtPoint(Address addressPoint) {
        return groupByPoint.get(addressPoint.getOffset());
    }

    public SubTable subTableAtPoint(Address addressPoint) {
        return subByPoint.get(addressPoint.getOffset());
    }

    /** Where in the image the given address point's value appears as a word. */
    public List<Address> occurrencesOf(Address addressPoint) {
        return occurrences.getOrDefault(addressPoint.getOffset(), List.of());
    }

    public void printSummary() {
        int real = 0, weak = 0, ctor = 0, orphan = 0;
        for (VtableGroup g : groups) {
            switch (g.kind()) {
                case REAL -> real++;
                case REAL_WEAK -> weak++;
                case CONSTRUCTION -> ctor++;
                case ORPHAN -> orphan++;
            }
        }
        log.accept("    Vtable groups:          " + groups.size());
        log.accept("      real (literal-loaded): " + real);
        log.accept("      real (weak, promoted): " + weak);
        log.accept("      construction vtables:  " + ctor);
        log.accept("      orphans:               " + orphan);
        log.accept("    VTTs:                   " + vtts.size());
        log.accept("      construction attributed by VTT:    " + attributedByVtt);
        log.accept("      construction attributed by offset: " + attributedByOffset);
        log.accept("      construction unattributed:         " + unattributedConstruction);
        if (chainSlackUsed > 0) {
            log.accept("    WARNING: alignment slack used while chaining: " + chainSlackUsed);
        }
        if (ctorPairsAgreed > 0 || ctorPairsMismatched > 0) {
            log.accept("      construction C/B pairs: " + ctorPairsAgreed
                    + " agreed on the vbase offset, " + ctorPairsMismatched + " did not");
            for (VtableGroup g : groups) {
                if (g.kind() != Kind.CONSTRUCTION) continue;
                int at = g.evidence().indexOf("no C table for");
                if (at >= 0) {
                    log.accept("        " + g.head() + " " + g.evidence().substring(at));
                }
            }
        }
        if (rejectedOffsetToTop > 0) {
            log.accept("      candidate slots rejected on an impossible offset-to-top "
                    + "(a word that is an address, not a displacement): "
                    + rejectedOffsetToTop);
        }
        if (headerGapsClosed > 0) {
            log.accept("      header words recovered from the gap to the preceding "
                    + "sub-table: " + headerGapsClosed + " tables");
            headerGapNotes.stream().limit(6).forEach(n -> log.accept("        " + n));
        }
        if (positiveOffsetToTop > 0) {
            log.accept("      B tables with a positive offset-to-top: "
                    + positiveOffsetToTop + " (legitimate: a shared virtual base can sit "
                    + "before the subobject being built)");
        }
        if (noOwnVtable > 0) {
            log.accept("      classes whose only tables are other classes' construction "
                    + "vtables: " + noOwnVtable);
        }
        if (vttsSplit > 0) {
            log.accept("      VTT runs split where the next class's VTT begins: " + vttsSplit);
        }
        if (importedRttiSlots > 0) {
            log.accept("      RTTI slots holding an imported typeinfo (a class from another "
                    + "module): " + importedRttiSlots);
        }
        if (constantsNotSlots > 0) {
            log.accept("      table walks stopped at a constant the file holds unrelocated "
                    + "(a vbase offset, not a slot): " + constantsNotSlots);
        }
        if (slotsRejected > 0) {
            log.accept("    WARNING: table walks stopped early by slot validation: "
                    + slotsRejected + " (" + rejectedAlign + " misaligned for ARM, "
                    + rejectedMode + " thumb-bit vs target mode)");
        }
        if (vbaseValidationFailures > 0) {
            log.accept("    WARNING: vbase header rejected by validation: "
                    + vbaseValidationFailures);
        }
        if (demotedExtraReal > 0) {
            log.accept("    WARNING: extra literal-loaded groups demoted to weak: "
                    + demotedExtraReal);
        }
        if (promotedWeak > 0) {
            log.accept("    WARNING: classes with no literal-loaded vtable, promoted: "
                    + promotedWeak);
        }
    }

    // ---------------------------------------------------------------
    //  Step 1a: raw sub-tables
    // ---------------------------------------------------------------

    /** A sub-table before its head is known: everything derivable from the RTTI slot alone. */
    private record Raw(Address rttiSlot, Address addressPoint, int offsetToTop,
                       long typeinfo, String className, List<Long> slots) { }

    private List<Raw> buildRawSubTables() throws Exception {
        List<Long> slotAddrs = findRttiSlots();
        Collections.sort(slotAddrs);

        List<Raw> raws = new ArrayList<>();
        for (int r = 0; r < slotAddrs.size(); r++) {
            if (cancelled()) break;

            long slotOff = slotAddrs.get(r);
            Address slot = space.getAddress(slotOff);
            long typeinfo = readWord(slot);
            String className = typeinfoToClassName.get(typeinfo);
            if (className == null) {
                className = importedSlotClass.get(slotOff);
                if (className != null) typeinfo = pseudoTypeinfo(className);
            }
            if (className == null) continue;

            // offset-to-top is always the word immediately before the typeinfo pointer,
            // whatever else precedes it.
            int offsetToTop;
            try {
                offsetToTop = memory.getInt(slot.subtract(PTR_SIZE));
            } catch (Exception e) {
                continue;   // start of the block: this cannot be a sub-table
            }
            // offset-to-top is a displacement inside one object, so it is bounded by the
            // largest object the program builds. sead::FixedSafeString<32> was picking up
            // two "vtables" at 0x8af55c and 0x8af95c with an offset-to-top of 854,016:
            // a run of 00xx0800 words, one of which happens to equal that class's typeinfo
            // address. The largest real one measured here is 8,508
            // (state::Mode<LetterDragItemWindow>), so a megabyte is generous by two orders
            // of magnitude and still rejects a word that is plainly an address.
            if (Math.abs((long) offsetToTop) > MAX_OFFSET_TO_TOP) {
                rejectedOffsetToTop++;
                continue;
            }

            long boundary;
            if (r + 1 < slotAddrs.size()) {
                // Stop before the next sub-table's offset-to-top word. Anything further
                // back belongs to the next sub-table's header, and a vbase-offset word is
                // a small integer that isFunctionPointer rejects anyway.
                boundary = slotAddrs.get(r + 1) - PTR_SIZE;
            } else {
                MemoryBlock block = memory.getBlock(slot);
                boundary = (block != null) ? block.getEnd().getOffset() + 1
                        : slotOff + 0x10000;
            }

            List<Long> slots = new ArrayList<>();
            Address addressPoint = slot.add(PTR_SIZE);
            long current = addressPoint.getOffset();
            while (current < boundary) {
                Address at = space.getAddress(current);
                long value;
                try {
                    value = readWord(at);
                } catch (Exception e) {
                    break;
                }
                if (!isFunctionPointer(at, value)) break;
                if (!plausibleSlot(at, value)) { slotsRejected++; break; }
                slots.add(value);
                current += PTR_SIZE;
            }
            if (slots.isEmpty()) continue;

            raws.add(new Raw(slot, addressPoint, offsetToTop, typeinfo, className, slots));
        }
        return raws;
    }

    /** Words in read-only memory pointing at a known typeinfo struct, minus typeinfo bodies. */
    private List<Long> findRttiSlots() throws Exception {
        List<Long> found = new ArrayList<>();
        for (MemoryBlock block : readOnlyBlocks()) {
            if (cancelled()) break;
            byte[] bytes = readBlock(block);
            if (bytes == null) continue;
            long base = block.getStart().getOffset();
            for (int i = 0; i + PTR_SIZE <= bytes.length; i += PTR_SIZE) {
                long value = readWord(bytes, i);
                if (!typeinfoToClassName.containsKey(value)) {
                    // An imported typeinfo: 0 in memory, named by its import record.
                    if (value != 0) continue;
                    Address at = space.getAddress(base + i);
                    boolean imported = false;
                    for (Reference ref : program.getReferenceManager().getReferencesFrom(at)) {
                        if (ref instanceof ExternalReference) { imported = true; break; }
                    }
                    if (!imported) continue;
                    String cls = importedTypeinfo.apply(at);
                    if (cls == null || cls.startsWith("__cxxabiv1")) continue;
                    importedSlotClass.put(base + i, cls);
                    importedRttiSlots++;
                    found.add(base + i);
                    continue;
                }
                long addr = base + i;
                // A typeinfo body holds base-class pointers to other typeinfos; those are
                // not vtable RTTI slots.
                if (isInsideTypeinfo(addr)) continue;
                found.add(addr);
            }
        }
        return found;
    }

    private boolean isInsideTypeinfo(long addr) {
        for (Map.Entry<Long, Integer> e : typeinfoSizes.entrySet()) {
            long start = e.getKey();
            if (addr >= start && addr < start + e.getValue()) return true;
        }
        return false;
    }

    // ---------------------------------------------------------------
    //  Step 1a2: what the raw tables and the VTTs say before any grouping
    // ---------------------------------------------------------------

    /** Address point -> the raw sub-table there. */
    private final Map<Long, Raw> rawByPoint = new HashMap<>();

    /** Class -> slot count of its own primary table, the longest one carrying its typeinfo. */
    private final Map<String, Integer> primarySlotCount = new HashMap<>();

    /**
     * Address points that begin an object of their own and so must not be chained onto the
     * table before them, even when they sit right after it.
     */
    private final Set<Long> objectStartPoints = new HashSet<>();

    private void indexRaws(List<Raw> raws) {
        for (Raw raw : raws) {
            rawByPoint.put(raw.addressPoint().getOffset(), raw);
            if (raw.offsetToTop() == 0) {
                primarySlotCount.merge(raw.className(), raw.slots().size(), Math::max);
            }
        }
        findSeparateObjects();
    }

    /**
     * Find the {@code _ZT_B1_} tables: virtual-base construction tables, which ARMCC emits
     * as objects in their own right.
     *
     * <p>They are indistinguishable from a real vtable's own virtual-base sub-table by
     * shape -- same vcall run, same negative offset-to-top -- and the two want opposite
     * treatment, since the real one continues its group and this one does not. The VTT
     * separates them. A VTT's entry 0 points at its owner's own primary table, which names
     * the owner; any other entry landing on a table that carries a <em>different</em>
     * class's typeinfo is a construction table emitted for that owner. A construction table
     * with a negative offset-to-top is a {@code _ZT_B1_}.
     *
     * <p>ARMCC emits the run C1..CN then B1_N..B1_1, so a C table and its B table are
     * adjacent only in the middle of the run -- which is exactly where the old code merged
     * the two into one struct spanning both.
     */
    private void findSeparateObjects() {
        for (PendingVtt pending : pendingVtts) {
            List<Raw> entries = new ArrayList<>();
            for (Address word : pending.words()) {
                try {
                    entries.add(rawByPoint.get(readWord(word)));
                } catch (Exception e) {
                    entries.add(null);
                }
            }
            if (entries.isEmpty() || entries.get(0) == null) continue;
            Raw first = entries.get(0);
            if (first.offsetToTop() != 0) continue;    // entry 0 names the owner's primary
            String owner = first.className();

            for (Raw entry : entries) {
                if (entry == null || entry.offsetToTop() >= 0) continue;
                if (entry.className().equals(owner)) continue;   // the owner's own secondary
                objectStartPoints.add(entry.addressPoint().getOffset());
            }
        }
    }

    /**
     * How many words sit in front of a sub-table's offset-to-top.
     *
     * <p>Two different runs can be there, and only one of them was ever handled before:
     *
     * <ul>
     * <li><b>vbase offsets</b> -- one per virtual base, on a table that starts a complete
     *     object (offset-to-top 0). These are never zero, so they can be validated
     *     against the bytes.</li>
     * <li><b>vcall offsets</b> -- on a table describing a <em>virtual base</em> subobject,
     *     one per virtual function of that base, with the destructor pair sharing one.
     *     Every slot the derived class does not override has a vcall offset of zero, so
     *     most of the run is zeros and the bytes cannot say how long it is. The count comes
     *     from the virtual base's own vtable instead: its slot count less one.</li>
     * </ul>
     *
     * <p>Rejecting zeros, as this used to, collapsed a ten-word vcall run to the single
     * non-zero word at its end and spilled the other nine into the previous table as
     * unwalked padding.
     *
     * @return the word count, or -1 when no authoritative count is available
     */
    private int headerWordsFor(Raw raw, List<String> notes) {
        if (raw.offsetToTop() == 0) {
            return expectedVbaseCount(raw.className());
        }

        // A non-zero offset-to-top means a base subobject. Only a *virtual* base carries
        // vcall offsets -- but a B table whose class is a plain secondary base still has a
        // vbase header of its own, one word per virtual base that class declares. That is
        // the ResourceGetSkeletal case: its B table is reached at +12, not the +8 a
        // headerless table would give, because ResourceGetSkeletal itself derives
        // virtually from ObjectResource. Treating it as headerless is what left a 4-byte
        // gap at 0x83e5b4 and made the table read 4 bytes short.
        String vbase = soleVirtualBase(raw.className());
        if (vbase == null) return expectedVbaseCount(raw.className());

        Integer slots = primarySlotCount.get(vbase);
        if (slots == null || slots < 1) {
            notes.add("no vtable found for virtual base " + vbase
                    + ", so the vcall run before " + raw.rttiSlot() + " could not be sized");
            return -1;
        }
        // The slot count has to match, or this secondary is not the one serving that
        // virtual base and sizing it as though it were would move the head into the
        // previous table's slots.
        if (raw.slots().size() != slots) return 0;
        return (slots - 1) + expectedVbaseCount(vbase);
    }

    /**
     * The one virtual base anywhere in a class's base closure, or null if there is not
     * exactly one.
     *
     * <p>The closure, not just the direct edges: a {@code _ZT_B1_} table carries the
     * typeinfo of the class that declares the virtual base, but a real vtable's own
     * virtual-base sub-table carries the most-derived class's typeinfo, and that class may
     * be several levels below the declaration. Both need the same answer.
     *
     * <p>Only an unambiguous answer is given. With two virtual bases in the closure there
     * are two vcall runs of different lengths and nothing here says which is which, so the
     * sub-table is left unsized rather than sized wrongly.
     */
    /** How many distinct virtual bases the class reaches, declared or inherited. */
    private int virtualBaseClosure(String className) {
        Set<String> found = new HashSet<>();
        Set<String> visited = new HashSet<>(List.of(className));
        Deque<String> work = new ArrayDeque<>(List.of(className));
        while (!work.isEmpty()) {
            for (BaseRef b : baseInfo.getOrDefault(work.poll(), List.of())) {
                if (b.isVirtual()) found.add(b.name());
                if (visited.add(b.name())) work.add(b.name());
            }
        }
        return found.size();
    }

    private String soleVirtualBase(String className) {
        Set<String> found = new HashSet<>();
        Set<String> visited = new HashSet<>();
        Deque<String> work = new ArrayDeque<>();
        work.add(className);
        visited.add(className);
        while (!work.isEmpty()) {
            List<BaseRef> bases = baseInfo.get(work.poll());
            if (bases == null) continue;
            for (BaseRef b : bases) {
                if (b.isVirtual()) found.add(b.name());
                if (visited.add(b.name())) work.add(b.name());
            }
        }
        return (found.size() == 1) ? found.iterator().next() : null;
    }

    // ---------------------------------------------------------------
    //  Step 1b: chain sub-tables into groups, deriving each head
    // ---------------------------------------------------------------

    private void chainGroups(List<Raw> raws) {
        List<SubTable> current = new ArrayList<>();
        String currentClass = null;
        List<String> pendingNotes = new ArrayList<>();

        for (Raw raw : raws) {
            SubTable chained = null;
            boolean ownObject = objectStartPoints.contains(raw.addressPoint().getOffset());
            if (!current.isEmpty() && !ownObject
                    && raw.typeinfo() == current.get(0).typeinfo()
                    && raw.offsetToTop() < 0) {
                chained = chainOnto(current.get(current.size() - 1), raw, pendingNotes);
            }

            if (chained != null) {
                current.add(chained);
                continue;
            }

            flushGroup(currentClass, current, pendingNotes);
            current = new ArrayList<>();
            pendingNotes = new ArrayList<>();
            currentClass = raw.className();
            current.add(startGroup(raw, pendingNotes));
        }
        flushGroup(currentClass, current, pendingNotes);
    }

    /**
     * A sub-table that continues a group: the contiguity guarantee puts its head exactly at
     * the previous sub-table's end, so the gap up to its offset-to-top word is its
     * vbase-offset header and needs no guessing.
     */
    private SubTable chainOnto(SubTable prev, Raw raw, List<String> notes) {
        Address prevEnd = prev.end();
        Address offsetToTopAddr = raw.rttiSlot().subtract(PTR_SIZE);
        long gap = offsetToTopAddr.getOffset() - prevEnd.getOffset();
        if (gap < 0 || gap % PTR_SIZE != 0) return null;

        int words = (int) (gap / PTR_SIZE);

        // Prefer the count the class graph fixes -- a vcall run is mostly zeros, so the
        // bytes cannot be asked how long it is.
        int header = headerWordsFor(raw, notes);
        if (header >= 0 && header <= words
                && readsAsHeaderWords(offsetToTopAddr.subtract((long) PTR_SIZE * header),
                        header)) {
            int slack = words - header;
            if (slack > 0) {
                if (slack > CHAIN_SLACK_WORDS && !allZero(prevEnd, slack)) return null;
                chainSlackUsed++;
                notes.add(slack + " word(s) before " + offsetToTopAddr
                        + " belong to no header (unwalked null slots or padding)");
            }
            return makeSubTable(offsetToTopAddr.subtract((long) PTR_SIZE * header),
                    raw, header);
        }

        // Fallback, for a sub-table the graph could not size: not all of the gap need be a
        // header. The slot walk stops at the first word that does not read as a function
        // pointer, so a table holding null slots -- an unresolved cross-module import, or a
        // pure virtual with no reference yet -- ends early and leaves those nulls in the
        // gap. Claim only the trailing run that actually reads as vbase offsets and leave
        // the rest unclaimed. Zeros are rejected here on purpose: without an authoritative
        // count there is nothing to stop a run of unwalked null slots being swallowed whole.
        header = Math.min(words, MAX_VBASE_WORDS);
        while (header > 0 && !readsAsVbaseOffsets(
                offsetToTopAddr.subtract((long) PTR_SIZE * header), header)) {
            header--;
        }
        int unclaimed = words - header;
        if (unclaimed > 0) {
            // Only an explained gap may be chained across. Null words are the slots the
            // walk could not confirm; anything else means these two tables are not one
            // object and joining them would invent a sub-table.
            if (unclaimed > CHAIN_SLACK_WORDS && !allZero(prevEnd, unclaimed)) return null;
            chainSlackUsed++;
            notes.add(unclaimed + " word(s) before " + offsetToTopAddr
                    + " belong to no header (unwalked null slots or padding)");
        }
        return makeSubTable(offsetToTopAddr.subtract((long) PTR_SIZE * header), raw, header);
    }

    /** rttiSlot offset -&gt; header word count forced by the preceding sub-table's end. */
    private final Map<Long, Integer> forcedHeader = new HashMap<>();

    /**
     * Header counts read off the gaps between consecutive sub-tables.
     *
     * <p>{@link #chainOnto} already does this <em>within</em> a group, where it is exact.
     * The same constraint holds <em>across</em> groups and was going unused: armcc emits a
     * class's construction tables one after another in VTT order, and everything here is
     * four-byte data that needs no alignment padding, so a gap between one sub-table's last
     * slot and the next one's offset-to-top word is the next one's header. Nothing else can
     * be there.
     *
     * <p>That is what the three B tables the checker flagged needed. Each starts a group of
     * its own -- a {@code _ZT_B1_} table is not chained onto its {@code _ZT_C*_} partner --
     * so the class graph was the only thing sizing them, and for a B table the graph cannot:
     * the run's length depends on which class the table's <em>name</em> leads with, and
     * whether that class's virtual base is its primary base. The bytes answer both at once.
     * {@code 0x8a26c0} wanted 9 words, {@code 0x8a2718} 10, {@code 0x83e5b4} 1, and the gaps
     * are exactly 9, 10 and 1.
     *
     * <p>Only consulted where the graph had no answer, so a count derived from a class's
     * declared virtual bases is never overridden by an accident of layout.
     */
    private void deriveHeadersFromContiguity(List<Raw> raws) {
        for (int i = 1; i < raws.size(); i++) {
            Raw prev = raws.get(i - 1);
            Raw next = raws.get(i);
            long prevEnd = prev.addressPoint().getOffset()
                    + (long) PTR_SIZE * prev.slots().size();
            long headWord = next.rttiSlot().getOffset() - PTR_SIZE;
            long gap = headWord - prevEnd;
            if (gap <= 0 || gap % PTR_SIZE != 0) continue;
            int words = (int) (gap / PTR_SIZE);
            if (words > MAX_VBASE_WORDS) continue;

            Address start = space.getAddress(prevEnd);
            MemoryBlock a = memory.getBlock(start);
            MemoryBlock b = memory.getBlock(next.rttiSlot());
            if (a == null || b == null || !a.equals(b)) continue;
            if (!readsAsHeaderWords(start, words)) continue;

            forcedHeader.put(next.rttiSlot().getOffset(), words);
        }
    }

    /**
     * A sub-table that starts a group. Nothing in front of it constrains the head, so the
     * vbase-offset count comes from the class's own virtual bases and is then validated
     * against the words actually there.
     */
    private SubTable startGroup(Raw raw, List<String> notes) {
        Address offsetToTopAddr = raw.rttiSlot().subtract(PTR_SIZE);

        // A _ZT_B1_ table starts a group of its own, and its header is a vcall run whose
        // words are mostly zero, so it is sized from the virtual base rather than read.
        //
        // Either sign counts. A positive offset-to-top looks impossible and was rejected
        // here, but armcc probe q2q3_nnfs.py shows it is legitimate on a B table: when a
        // shared virtual base is the *primary* base of one branch it can sit at a lower
        // address than the subobject being constructed, so its offset-to-top relative to
        // that subobject is positive. nn::fs::IStream puts IPositionable at 0 and
        // IOutputStream at +4, giving the +4 seen in ACNL. Only C tables are always 0.
        if (raw.offsetToTop() != 0) {
            if (raw.offsetToTop() > 0) positiveOffsetToTop++;
            int vcall = headerWordsFor(raw, notes);
            if (vcall > 0 && readsAsHeaderWords(
                    offsetToTopAddr.subtract((long) PTR_SIZE * vcall), vcall)) {
                return makeSubTable(offsetToTopAddr.subtract((long) PTR_SIZE * vcall),
                        raw, vcall);
            }
            // The graph could not size it. The gap back to the preceding sub-table can.
            Integer forced = forcedHeader.get(raw.rttiSlot().getOffset());
            if (forced != null && forced > 0) {
                noteHeaderGap(raw, forced);
                return makeSubTable(offsetToTopAddr.subtract((long) PTR_SIZE * forced),
                        raw, forced);
            }
            return makeSubTable(offsetToTopAddr, raw, 0);
        }

        int expected = expectedVbaseCount(raw.className());
        if (expected > 0) {
            Address head = offsetToTopAddr.subtract((long) PTR_SIZE * expected);
            // A run longer than the class's virtual-base count carries vcall offsets as
            // well, and those are normally zero, so it has to be validated with the
            // permissive reader or the first zero throws the header away.
            boolean mixed = expected > declaredVbaseCount(raw.className());
            boolean ok = mixed ? readsAsHeaderWords(head, expected)
                               : readsAsVbaseOffsets(head, expected);
            // One more word reading as a vbase offset means the count is short and the
            // head is landing inside the header rather than on it. Only meaningful when
            // the count came from counting; a measured run already knows where it starts.
            if (ok && !mixed && readsAsVbaseOffsets(head.subtract(PTR_SIZE), 1)) {
                ok = false;
                notes.add("vbase header ambiguous: word before " + head
                        + " also reads as a vbase offset");
            }
            if (ok) return makeSubTable(head, raw, expected);
            vbaseValidationFailures++;
            notes.add("expected " + expected + " vbase word(s) before " + offsetToTopAddr
                    + " but they did not validate; assuming none");
            Integer forced = forcedHeader.get(raw.rttiSlot().getOffset());
            if (forced != null && forced > 0) {
                noteHeaderGap(raw, forced);
                return makeSubTable(offsetToTopAddr.subtract((long) PTR_SIZE * forced),
                        raw, forced);
            }
        }
        // A class with no virtual bases has no header, and that is an answer, not a gap --
        // so the contiguity rule is deliberately not consulted here. Otherwise every
        // ordinary vtable that happened to sit a word or two after the one before it would
        // grow a header out of the padding.
        return makeSubTable(offsetToTopAddr, raw, 0);
    }

    /**
     * How many of a header's words, counting from the outermost, are vbase offsets rather
     * than vcall offsets. armcc's order is {@code [vbase][vcall]} (open answers Q2), and
     * the count of vbase words is a property of the class whose <em>subobject</em> this
     * sub-table describes -- its own declared virtual bases.
     *
     * <p>For a table at offset-to-top 0 that class is the table's own; for a base
     * sub-table it is the base sitting at {@code -offsetToTop}, which is what a
     * {@code _ZT_B1_} name leads with. That distinction is the whole of the difference
     * between {@code 0x8a26c0} (led by {@code IPositionable}, which declares no virtual
     * base of its own, so all nine words are vcall) and {@code 0x8a2718} (led by
     * {@code IOutputStream}, which declares one, so it is one vbase word then nine vcall).
     *
     * <p>Labelling only. The total comes from the bytes and the class graph; this just
     * says where to draw the line inside it, and errs towards "vcall" when the leading
     * class cannot be identified.
     */
    private int vbaseWordsIn(Raw raw, int total) {
        if (total <= 0) return 0;
        String leading = raw.className();
        if (raw.offsetToTop() != 0) {
            leading = null;
            int want = -raw.offsetToTop();
            for (BaseRef b : baseInfo.getOrDefault(raw.className(), List.of())) {
                if (b.isVirtual() || b.offset() != want) continue;
                if (leading != null && !leading.equals(b.name())) return 0;   // ambiguous
                leading = b.name();
            }
            // Not a direct base: the subobject can sit inside one, at the sum of the
            // offsets along a chain of non-virtual bases. AcFishMuseumRiver's secondary at
            // offset-to-top -208 serves a base of AcFishMuseumBase, not of River itself;
            // looking only at direct bases found nothing, called its vbase word 580 a vcall
            // word, and predicted _ZTv thunks for 56 bodies that adjust by a constant.
            if (leading == null) {
                leading = nonVirtualBaseAt(raw.className(), want, 0, 0);
                // ...but only when the words agree: a vbase offset in these tables points
                // forward and is positive. AcFsMuDefault's table at 0x2d3a0 is nine words
                // of -552/-344 in front of offset-to-top -552 -- a virtual base's vcall run
                // -- and a non-virtual chain that happened to reach offset 552 made all nine
                // "vbase", which lost the genuine _ZTv0_n12_ thunk at 0x1ca40.
                if (leading != null && !allPositive(raw, total)) leading = null;
            }
            // A non-virtual base's secondary carries no vcall offsets at all -- those exist
            // only in a virtual base subobject's table -- so its whole header is vbase
            // offsets, however many virtual bases it reached them through. Counting only
            // the base's *declared* ones was 0 for the fish-museum bases in ModuleMusFish,
            // whose virtual base is inherited: the vbase word 344 in front of the
            // offset-to-top -208 table at 0x2d368 was read as a vcall word, and the two
            // destructor thunks in it (0x1aef8 "sub r0,r0,#0xd0") were named _ZTv0_n12_
            // when they are _ZThn208_.
            // As many vbase words as virtual bases the base can reach -- inherited ones
            // included, which the declared count missed for the fish-museum bases (0 declared,
            // one inherited, header [344]). Not the whole header: nn::fs's tables are one
            // vbase word then nine vcall words, and counting all ten as vbase lost nine _ZTv
            // thunks at 0x8a26f0 (K1).
            if (leading != null) {
                return Math.min(Math.max(declaredVbaseCount(leading),
                        virtualBaseClosure(leading)), total);
            }
            leading = soleVirtualBase(raw.className());
            // Unidentified: all vcall, as before. (Counting the leading positive words as
            // vbase offsets was tried and is wrong: nn::fs's virtual-base tables carry
            // positive vcall offsets, and K1 lost nine _ZTv thunks at 0x8a26f0 to it. The
            // sign is only safe as a check on a base found by offset, above.)
            if (leading == null) return 0;
            if (leading == null) return 0;
        }
        // The *declared* count, not expectedVbaseCount: that one is the whole header run
        // (max of the virtual-base count and what the deepest __offset_flags implies), and
        // on a mixed header it already includes the vcall words. IInputStream declares one
        // virtual base and carries a ten-word header; the split is 1 + 9, not 10 + 0.
        return Math.min(declaredVbaseCount(leading), total);
    }

    /** The header's words, outermost first, for a sub-table with {@code total} of them. */
    private int[] headerWords(Raw raw, int total) {
        int[] w = new int[total];
        Address head = raw.rttiSlot().subtract((long) PTR_SIZE * (1 + total));
        for (int i = 0; i < total; i++) {
            try {
                w[i] = memory.getInt(head.add((long) PTR_SIZE * i));
            } catch (Exception e) {
                w[i] = 0;
            }
        }
        return w;
    }

    private boolean allPositive(Raw raw, int total) {
        for (int v : headerWords(raw, total)) if (v <= 0) return false;
        return true;
    }

    /**
     * The class whose subobject sits at byte {@code want} inside {@code cls}, reached through
     * non-virtual bases only (a virtual base has no fixed offset), or null. Depth-first,
     * accumulating each base's offset; a non-unique answer is null.
     */
    private String nonVirtualBaseAt(String cls, int want, int at, int depth) {
        if (depth > 16) return null;
        String found = null;
        for (BaseRef b : baseInfo.getOrDefault(cls, List.of())) {
            if (b.isVirtual()) continue;
            int here = at + b.offset();
            // The outermost class at the offset: its sub-table is the one being read.
            String hit = (here == want) ? b.name()
                    : nonVirtualBaseAt(b.name(), want, here, depth + 1);
            if (hit == null) continue;
            if (found != null && !found.equals(hit)) return null;
            found = hit;
        }
        return found;
    }

    private void noteHeaderGap(Raw raw, int words) {
        headerGapsClosed++;
        if (headerGapNotes.size() < 6) {
            headerGapNotes.add(raw.className() + " at " + raw.rttiSlot() + ": " + words
                    + " header word(s) taken from the gap to the preceding sub-table");
        }
    }

    private SubTable makeSubTable(Address head, Raw raw, int vbaseCount) {
        int[] vbases = new int[vbaseCount];
        for (int i = 0; i < vbaseCount; i++) {
            try {
                vbases[i] = memory.getInt(head.add((long) PTR_SIZE * i));
            } catch (Exception e) {
                vbases[i] = 0;
            }
        }
        return new SubTable(head, raw.rttiSlot().subtract(PTR_SIZE), raw.rttiSlot(),
                raw.addressPoint(), raw.offsetToTop(), vbaseCount,
                vbaseWordsIn(raw, vbaseCount), vbases,
                raw.typeinfo(), List.copyOf(raw.slots()));
    }

    private void flushGroup(String className, List<SubTable> subs, List<String> notes) {
        if (className == null || subs.isEmpty()) return;
        VtableGroup group = new VtableGroup(className, subs);
        for (String n : notes) group.note(n);
        if (!subs.get(0).isPrimary()) {
            // Not malformed by itself. Construction vtables sort with ordinary const data,
            // so the _ZT_B1_ half of a pair can stand alone rather than chaining onto the
            // _ZT_C1_ half. Classification still applies; only note what was seen.
            group.note("starts with offset-to-top " + subs.get(0).offsetToTop()
                    + " rather than 0");
        }
        groups.add(group);
        groupByHead.put(group.head().getOffset(), group);
        for (SubTable s : subs) {
            groupByPoint.put(s.addressPoint().getOffset(), group);
            subByPoint.put(s.addressPoint().getOffset(), s);
        }
    }

    /** Every word in the run is zero: slots the forward walk could not confirm. */
    private boolean allZero(Address start, int count) {
        for (int i = 0; i < count; i++) {
            try {
                if (memory.getInt(start.add((long) PTR_SIZE * i)) != 0) return false;
            } catch (Exception e) {
                return false;
            }
        }
        return true;
    }

    /**
     * Every word reads as a plausible header word: aligned, bounded, not code. Zero is
     * allowed -- a vcall offset is zero for every slot the derived class does not override,
     * and in the measured run nine of ten words are zero.
     */
    private boolean readsAsHeaderWords(Address start, int count) {
        for (int i = 0; i < count; i++) {
            int v;
            try {
                v = memory.getInt(start.add((long) PTR_SIZE * i));
            } catch (Exception e) {
                return false;
            }
            if (v % PTR_SIZE != 0) return false;
            if (Math.abs(v) > MAX_VBASE_OFFSET) return false;
            if (v != 0 && looksLikeCode(start.add((long) PTR_SIZE * i), v)) return false;
        }
        return true;
    }

    /**
     * Whether a header-word candidate is really a code pointer. In a relocated image a
     * constant the file holds unrelocated is never one, whatever it points at.
     */
    private boolean looksLikeCode(Address at, int v) {
        long value = Integer.toUnsignedLong(v);
        if (isUnrelocatedConstant(at, value)) return false;
        return isExecutable(value);
    }

    /** Every word reads as a plausible vbase offset: aligned, bounded, nonzero, not code. */
    private boolean readsAsVbaseOffsets(Address start, int count) {
        for (int i = 0; i < count; i++) {
            int v;
            try {
                v = memory.getInt(start.add((long) PTR_SIZE * i));
            } catch (Exception e) {
                return false;
            }
            if (v == 0 || v % PTR_SIZE != 0) return false;
            if (Math.abs(v) > MAX_VBASE_OFFSET) return false;
            if (looksLikeCode(start.add((long) PTR_SIZE * i), v)) return false;
        }
        return true;
    }

    /** Distinct virtual bases anywhere in the class's transitive base closure. */
    private int expectedVbaseCount(String className) {
        Integer cached = expectedVbaseCache.get(className);
        if (cached != null) return cached;

        Set<String> virtualBases = new HashSet<>();
        Set<String> visited = new HashSet<>();
        Deque<String> work = new ArrayDeque<>();
        work.add(className);
        visited.add(className);
        // The furthest-back header word any virtual base names, as a byte offset from the
        // address point. Always negative.
        int deepest = 0;
        while (!work.isEmpty()) {
            List<BaseRef> bases = baseInfo.get(work.poll());
            if (bases == null) continue;
            for (BaseRef b : bases) {
                if (b.isVirtual()) {
                    virtualBases.add(b.name());
                    if (b.offset() < deepest) deepest = b.offset();
                }
                if (visited.add(b.name())) work.add(b.name());
            }
        }

        // Counting virtual bases is not the same as measuring the header, and where the
        // two disagree the header is what the typeinfo actually states. A virtual base's
        // __offset_flags gives the byte offset, from the address point, of the word
        // holding its vbase offset -- so the run reaches back at least that far.
        //
        // Measured here: the four ObjectResource-deriving classes say -12, which is one
        // word and agrees with the count. nn::fs::IInputStream and nn::fs::IOutputStream
        // say -48 while declaring a single virtual base, which is a run of (48-8)/4 = 10
        // words. Predicting 1 for those probed a word that is not a vbase offset at all,
        // found the word before it equally plausible, and threw the whole header away --
        // which is the "vbase header rejected by validation: 8" warning, and why their
        // construction tables came out 44 bytes instead of 92 and with an offset-to-top
        // of +4: every read after the head was one run short.
        int fromOffsets = (deepest < -PTR_SIZE * 2) ? (-deepest - PTR_SIZE * 2) / PTR_SIZE : 0;
        int count = Math.max(virtualBases.size(), fromOffsets);
        if (count > MAX_VBASE_WORDS) count = MAX_VBASE_WORDS;
        expectedVbaseCache.put(className, count);
        vbaseDeclaredCache.put(className, virtualBases.size());
        return count;
    }

    /**
     * How many of a primary table's header words are vbase offsets proper.
     *
     * <p>When the measured run is longer than the number of virtual bases, the extra words
     * are vcall offsets, and those are normally <em>zero</em>. That matters because the
     * two kinds have to be validated differently: a vbase offset is a real displacement
     * and a zero one would be meaningless, while a zero vcall offset is the common case.
     * Validating a mixed run as if it were all vbase offsets rejects it on the first zero.
     */
    private int declaredVbaseCount(String className) {
        expectedVbaseCount(className);          // fills both caches
        Integer declared = vbaseDeclaredCache.get(className);
        return (declared == null) ? 0 : declared;
    }

    private final Map<String, Integer> vbaseDeclaredCache = new HashMap<>();

    // ---------------------------------------------------------------
    //  Step 1c: one pass for literal occurrences and VTT runs
    // ---------------------------------------------------------------

    private void scanMemoryWords(List<Raw> raws) throws Exception {
        // Address points come from the raw sub-tables, not from subByPoint, because this
        // now runs before the groups exist. It is the same set either way: the address
        // point is rttiSlot+4 whatever a sub-table's header turns out to be.
        Set<Long> points = new HashSet<>();
        for (Raw raw : raws) points.add(raw.addressPoint().getOffset());
        List<PendingVtt> runs = new ArrayList<>();

        // A VTT lives in the same read-only data region as the vtables it points at, which
        // is the region findRttiSlots already agreed on. Do not re-derive it from the
        // write flag: a 3DS ELF's .rodata is mapped writable.
        Set<String> vttBlocks = new HashSet<>();
        for (MemoryBlock b : readOnlyBlocks()) vttBlocks.add(b.getStart().toString());

        for (MemoryBlock block : memory.getBlocks()) {
            if (cancelled()) break;
            if (!block.isInitialized() || !block.isRead()) continue;
            byte[] bytes = readBlock(block);
            if (bytes == null) continue;
            long base = block.getStart().getOffset();
            boolean scanForVtt = vttBlocks.contains(block.getStart().toString());

            List<Address> run = new ArrayList<>();
            for (int i = 0; i + PTR_SIZE <= bytes.length; i += PTR_SIZE) {
                long value = readWord(bytes, i);
                Address at = space.getAddress(base + i);

                if (points.contains(value)) {
                    occurrences.computeIfAbsent(value, k -> new ArrayList<>()).add(at);
                    if (scanForVtt) {
                        run.add(at);
                        continue;
                    }
                }
                if (scanForVtt && !run.isEmpty()) {
                    if (run.size() >= MIN_VTT_ENTRIES) runs.add(new PendingVtt(run));
                    run = new ArrayList<>();
                }
            }
            if (scanForVtt && run.size() >= MIN_VTT_ENTRIES) runs.add(new PendingVtt(run));
        }

        pendingVtts.addAll(runs);
    }

    private record PendingVtt(List<Address> words) { }

    private final List<PendingVtt> pendingVtts = new ArrayList<>();

    /**
     * Name each run and hand it to its owner. A VTT leads with a pointer into its owner's
     * own primary table, and ARMCC emits it in a section named after the vtable, so it
     * abuts the owner's group -- on either side, since the order follows creation order.
     */
    private void resolveVtts() {
        for (PendingVtt pending : pendingVtts) {
            List<Address> words = new ArrayList<>();
            List<Address> entries = new ArrayList<>();
            for (Address word : pending.words()) {
                try {
                    entries.add(space.getAddress(readWord(word)));
                    words.add(word);
                } catch (Exception e) {
                    // unreadable word: leave it out of both lists
                }
            }
            // Two VTTs can sit back to back: one after its owner's vtable, the next before
            // its owner's. In ModuleMusFish, AcFsMuWander's VTT (after _ZTV12AcFsMuWander)
            // runs straight into AcFsMuDefault's (before _ZTV13AcFsMuDefault at 0x2d2a4), and
            // read as one run it made Default's own vtable a "construction vtable for Wander".
            // The group that starts right where the run ends owns the tail of the run from
            // the entry naming its primary. (Splitting at any entry that reached a
            // non-ancestor was tried first and cut AcFsMuCarp's single VTT into three.)
            int split = -1;
            if (!words.isEmpty()) {
                long after = words.get(words.size() - 1).getOffset() + PTR_SIZE;
                VtableGroup next = groupByHead.get(after);
                VtableGroup first = entries.isEmpty() ? null
                        : groupByPoint.get(entries.get(0).getOffset());
                // Only when the next group is another class: nn::fs::FileStream's own VTT
                // points at its own primary a second time (a sub-VTT), which is no seam.
                if (next != null && first != null && next.className().equals(first.className())) {
                    next = null;
                }
                if (next != null) {
                    for (int k = 1; k < entries.size(); k++) {
                        if (entries.get(k).equals(next.primary().addressPoint())) {
                            split = k;
                            break;
                        }
                    }
                }
            }
            if (split > 0) {
                addVtt(words.subList(0, split), entries.subList(0, split));
                addVtt(words.subList(split, words.size()),
                        entries.subList(split, entries.size()));
                vttsSplit++;
            } else {
                addVtt(words, entries);
            }
        }
    }

    private int vttsSplit = 0;

    private void addVtt(List<Address> words, List<Address> entries) {
        if (entries.size() < MIN_VTT_ENTRIES) return;
        VtableGroup owner = groupByPoint.get(entries.get(0).getOffset());
        if (owner == null) return;
        // Entry 0 must land on a group's *primary* address point, not partway in.
        if (!owner.primary().addressPoint().equals(entries.get(0))) return;

        Address start = words.get(0);
        Vtt vtt = new Vtt(start, PTR_SIZE * entries.size(), owner.className(),
                List.copyOf(entries));
        vtts.add(vtt);
        for (Address word : words) vttWordAddrs.add(word.getOffset());

        if (owner.vtt() == null) owner.setVtt(vtt);
        if (!abuts(vtt, owner)) {
            owner.note("VTT at " + start + " is not adjacent to the group");
        }
    }


    private boolean abuts(Vtt vtt, VtableGroup group) {
        Address groupEnd = group.subs().get(group.subs().size() - 1).end();
        long slack = (long) PTR_SIZE * (CHAIN_SLACK_WORDS + 1);
        long afterGroup = vtt.start().getOffset() - groupEnd.getOffset();
        long beforeGroup = group.head().getOffset() - vtt.end().getOffset();
        return (afterGroup >= 0 && afterGroup <= slack)
                || (beforeGroup >= 0 && beforeGroup <= slack);
    }

    // ---------------------------------------------------------------
    //  Step 1d/1e: classify, and say whose table each one is
    // ---------------------------------------------------------------

    //
    // vtables.md offers the literal-load test as the decisive discriminator: a real
    // vtable's address point is loaded from constructor code, a construction vtable is
    // only ever read out of a VTT. On these images that test is simply not available,
    // and believing it does active harm. Measured on ACNL v1.4 code.bin:
    //
    //   * No vtable address point appears as a word in executable memory at all. The
    //     literal pool holds unrelocated values, so a byte scan finds nothing.
    //   * getReferencesTo(point) on a REAL vtable returns only the VTT word that points
    //     at it -- its constructor's pool word was never typed, so no reference exists.
    //   * getReferencesTo(point) on a CONSTRUCTION vtable can return a genuine
    //     "str rN,[r0,#0]" in a constructor, because Ghidra constant-propagates through
    //     the "ldr rN,[rN,#0xc]" that read it out of the VTT in the first place.
    //
    // So code references point the wrong way as often as the right way. What does hold
    // is the structure the VTT itself gives us:
    //
    //   * A VTT's entry 0 points at its owner's own primary address point. That names
    //     both the VTT and the owner's real vtable.
    //   * A construction vtable is reachable only through a VTT, at an entry past 0.
    //   * Therefore a group that no VTT points into can only be reached by code, which
    //     makes it that class's own vtable -- and this is the common case, since classes
    //     without virtual bases have neither VTTs nor construction vtables.
    //
    // Code references are still collected, but as reported evidence only.
    //

    /** One VTT pointing into a group, and at which entry. */
    private record VttHit(Vtt vtt, int entryIndex) { }

    private final Map<Long, List<VttHit>> vttHitsByPoint = new HashMap<>();

    private void classifyGroups() {
        indexVttHits();

        for (VtableGroup group : groups) {
            VttHit ownEntry = null;      // a VTT whose entry 0 is this group's primary
            VttHit foreign = null;       // a VTT of another class reaching this group
            long primaryPoint = group.primary().addressPoint().getOffset();

            for (VttHit hit : hitsOn(group)) {
                if (hit.entryIndex() == 0
                        && hit.vtt().entries().get(0).getOffset() == primaryPoint) {
                    ownEntry = hit;
                } else if (!hit.vtt().ownerClass().equals(group.className())) {
                    if (foreign == null) foreign = hit;
                }
            }

            if (ownEntry != null) {
                group.setKind(Kind.REAL);
                group.setVtt(ownEntry.vtt());
                group.note("entry 0 of the VTT at " + ownEntry.vtt().start()
                        + ", so this is " + group.className() + "'s own vtable");
            } else if (foreign != null) {
                group.setKind(Kind.CONSTRUCTION);
                group.setDerivedOwner(foreign.vtt().ownerClass());
                group.note("reached from " + foreign.vtt().ownerClass() + "'s VTT at "
                        + foreign.vtt().start() + " entry " + foreign.entryIndex());
                attributedByVtt++;
            } else if (hitsOn(group).isEmpty()) {
                // Nothing in read-only data points at it, so only code can reach it.
                group.setKind(Kind.REAL);
                group.note("no VTT reaches it, so it is reached from code");
            } else {
                // Reached only by its own class's VTT past entry 0: a secondary
                // sub-table of its own vtable that did not chain into the group.
                group.setKind(Kind.REAL_WEAK);
                group.note("reached only from its own class's VTT");
            }

            List<Address> loaders = codeLoadersOf(group.primary().addressPoint());
            if (!loaders.isEmpty()) {
                group.note(loaders.size() + " direct code reference(s), e.g. "
                        + loaders.get(0) + " (evidence only)");
            }
        }
    }

    private void indexVttHits() {
        for (Vtt vtt : vtts) {
            for (int i = 0; i < vtt.entries().size(); i++) {
                vttHitsByPoint.computeIfAbsent(vtt.entries().get(i).getOffset(),
                        k -> new ArrayList<>()).add(new VttHit(vtt, i));
            }
        }
    }

    private List<VttHit> hitsOn(VtableGroup group) {
        List<VttHit> out = new ArrayList<>();
        for (SubTable s : group.subs()) {
            List<VttHit> hits = vttHitsByPoint.get(s.addressPoint().getOffset());
            if (hits != null) out.addAll(hits);
        }
        return out;
    }

    /**
     * Every class should end up with exactly one group that is its own vtable. Where the
     * structure left it ambiguous, prefer the one a VTT named as its own, then the one
     * with the most sub-tables, then the lowest address -- and never leave a class with
     * none, because a vtable wrongly removed is worse than one wrongly kept.
     */
    private void reconcilePerClass() {
        Map<String, List<VtableGroup>> byClass = new LinkedHashMap<>();
        for (VtableGroup g : groups) {
            byClass.computeIfAbsent(g.className(), k -> new ArrayList<>()).add(g);
        }

        for (Map.Entry<String, List<VtableGroup>> e : byClass.entrySet()) {
            List<VtableGroup> candidates = e.getValue();
            List<VtableGroup> reals = new ArrayList<>();
            for (VtableGroup g : candidates) if (g.kind() == Kind.REAL) reals.add(g);

            if (reals.size() > 1) {
                VtableGroup best = bestCandidate(reals);
                for (VtableGroup g : reals) {
                    if (g == best) continue;
                    VttHit foreign = firstForeignHit(g);
                    if (foreign != null) {
                        g.setKind(Kind.CONSTRUCTION);
                        g.setDerivedOwner(foreign.vtt().ownerClass());
                        g.note("demoted: " + e.getKey() + " has a better own vtable, and "
                                + foreign.vtt().ownerClass() + "'s VTT reaches this one");
                        attributedByVtt++;
                    } else {
                        g.setKind(Kind.REAL_WEAK);
                        g.note("demoted: another group for " + e.getKey()
                                + " is a better own vtable");
                    }
                    demotedExtraReal++;
                }
            } else if (reals.isEmpty()) {
                // Only a group that no other class's VTT reaches may be promoted. Being
                // reached from another class's VTT is what *defines* a construction
                // vtable, and no amount of resemblance to the class's own table overrides
                // it (armcc probe Q7). Promoting regardless is why AcFishCommon's and
                // AcObjectBase's tables at 0x83def0 and 0x83df98 came out REAL_WEAK when
                // they are AcFishFieldBase's C tables.
                //
                // A class left with nothing is then a class whose own vtable really is
                // absent from this image -- an abstract base whose _ZTV was eliminated --
                // which is a truthful answer rather than a lost vtable.
                List<VtableGroup> promotable = new ArrayList<>();
                for (VtableGroup g : candidates) {
                    if (firstForeignHit(g) == null) promotable.add(g);
                }
                VtableGroup best = bestCandidate(promotable);
                if (best != null && !best.isReal()) {
                    best.setKind(Kind.REAL_WEAK);
                    best.setDerivedOwner(null);
                    best.note("promoted: no group for " + e.getKey()
                            + " was identifiable as its own vtable");
                    promotedWeak++;
                } else if (best == null) {
                    noOwnVtable++;
                }
            }
        }

        for (VtableGroup g : groups) {
            if (g.kind() == Kind.CONSTRUCTION && g.derivedOwner() == null) {
                String owner = attributeBySecondaryOffset(g);
                if (owner != null) {
                    g.setDerivedOwner(owner);
                    g.note("attributed to " + owner + " by secondary offset-to-top");
                    attributedByOffset++;
                } else {
                    unattributedConstruction++;
                }
            }
        }
    }

    private VttHit firstForeignHit(VtableGroup group) {
        for (VttHit hit : hitsOn(group)) {
            if (!hit.vtt().ownerClass().equals(group.className())) return hit;
        }
        return null;
    }

    private VtableGroup bestCandidate(List<VtableGroup> candidates) {
        VtableGroup best = null;
        for (VtableGroup g : candidates) {
            if (g.primary().offsetToTop() != 0) continue;
            if (best == null) { best = g; continue; }
            int cmp = Boolean.compare(g.vtt() != null, best.vtt() != null);
            if (cmp == 0) cmp = Integer.compare(g.subs().size(), best.subs().size());
            if (cmp == 0) cmp = -g.head().compareTo(best.head());
            if (cmp > 0) best = g;
        }
        if (best == null && !candidates.isEmpty()) best = candidates.get(0);
        return best;
    }

    /**
     * A construction table's secondary offset-to-top describes the <em>derived</em>
     * class's layout, not the base's. So the owner is the class that both derives from
     * this group's class and places a virtual base at that offset. Only a unique answer
     * is trusted; the cost of guessing here is a wrong label.
     */
    private String attributeBySecondaryOffset(VtableGroup group) {
        if (group.subs().size() < 2) return null;
        int wanted = -group.subs().get(1).offsetToTop();
        if (wanted <= 0) return null;

        String found = null;
        for (Map.Entry<String, VtableGroup> e : realGroups().entrySet()) {
            String candidate = e.getKey();
            if (candidate.equals(group.className())) continue;
            if (!derivesNonVirtually(candidate, group.className())) continue;
            if (!placesVbaseAt(e.getValue(), wanted)) continue;
            if (found != null) return null;   // ambiguous
            found = candidate;
        }
        return found;
    }

    private boolean derivesNonVirtually(String derived, String base) {
        List<BaseRef> bases = baseInfo.get(derived);
        if (bases == null) return false;
        for (BaseRef b : bases) {
            if (!b.isVirtual() && b.name().equals(base)) return true;
        }
        return false;
    }

    private boolean placesVbaseAt(VtableGroup group, int offset) {
        for (int v : group.primary().vbaseOffsets()) {
            if (v == offset) return true;
        }
        return false;
    }

    /**
     * Instructions that reference this address point directly.
     *
     * <p>Reported as evidence only, never to classify: see the note above
     * {@link #classifyGroups()}. There is deliberately no hop back through an
     * intermediate data word here. A hop was tried and had to be removed -- on this
     * image the only thing referring to a vtable's address point is usually the VTT word
     * pointing at it, so hopping back turned "code reads the VTT" into "code literal-loads
     * this table" and made every construction vtable look real.
     */
    public List<Address> codeLoadersOf(Address point) {
        List<Address> out = new ArrayList<>();
        for (Reference r : program.getReferenceManager().getReferencesTo(point)) {
            Address from = r.getFromAddress();
            if (isExecutableAddress(from)) out.add(from);
        }
        return out;
    }

    // ---------------------------------------------------------------
    //  Reporting helpers used by the diagnostic script
    // ---------------------------------------------------------------

    /**
     * How many leading bytes this group shares with its class's real group, which is what
     * makes a construction vtable look like the real thing at a glance.
     */
    public int leadingIdentityBytes(VtableGroup group) {
        VtableGroup real = realGroupFor(group.className());
        if (real == null || real == group) return -1;
        int limit = Math.min(LEADING_IDENTITY_BYTES,
                Math.min(groupLength(group), groupLength(real)));
        int same = 0;
        for (int i = 0; i < limit; i++) {
            try {
                if (memory.getByte(group.head().add(i)) != memory.getByte(real.head().add(i))) {
                    break;
                }
            } catch (Exception e) {
                break;
            }
            same++;
        }
        return same;
    }

    public int groupLength(VtableGroup group) {
        SubTable last = group.subs().get(group.subs().size() - 1);
        return (int) (last.end().getOffset() - group.head().getOffset());
    }

    /** VTT runs holding a pointer into this group, whatever their owner. */
    public List<Vtt> vttsReaching(VtableGroup group) {
        Set<Long> points = new HashSet<>();
        for (SubTable s : group.subs()) points.add(s.addressPoint().getOffset());
        List<Vtt> out = new ArrayList<>();
        for (Vtt v : vtts) {
            for (Address e : v.entries()) {
                if (points.contains(e.getOffset())) { out.add(v); break; }
            }
        }
        return out;
    }

    // ---------------------------------------------------------------
    //  Low-level helpers
    // ---------------------------------------------------------------

    /**
     * A second opinion on a candidate slot, to stop a table walking off its end.
     *
     * <p>{@link #isFunctionPointer} asks only whether the word lands in an executable
     * block, and a surprising amount of non-code passes that: UTF-16 text runs like
     * {@code 0x00610069} ("ia") and {@code 0x0031002e} (".1") sit squarely inside the
     * {@code .text} range, which is how {@code (anonymous_namespace)::Delegate} at
     * {@code 0x89d708} came out with 48 slots of which everything from slot 3 on was
     * string data.
     *
     * <p>Two further tests, both cheap and both things a real slot cannot fail:
     * <ul>
     * <li><b>Mid-function.</b> A vtable slot is an entry point. A word pointing into the
     *     middle of a function that starts somewhere else is not a slot, whatever block it
     *     is in.</li>
     * <li><b>Thumb bit.</b> Bit 0 of a slot says how to enter the target, so it has to
     *     agree with the mode the target is actually disassembled in. Where the target has
     *     no mode recorded yet nothing is claimed -- an undisassembled address is unknown,
     *     not wrong, and truncating a real table on a guess is worse than one long one.
     *     {@code nn::nex::DataStorePersistenceTarget} at {@code 0x8fdcd0} is the case this
     *     catches: slot 0 is even while its target is Thumb.</li>
     * </ul>
     */
    private boolean plausibleSlot(Address at, long value) {
        if (value == 0) return true;   // external; isFunctionPointer already required a ref
        Address target = space.getAddress(value & ~1L);
        if (target == null) return false;

        // An ARM entry point is 4-byte aligned, always. This is the one test here that
        // cannot produce a false positive, because the alignment is an architectural
        // guarantee rather than a guess about intent.
        //
        // It is also what catches the runaway table. UTF-16 string data inside the .text
        // address range passes every "is this executable memory" test -- 0x0031002e (".1")
        // is a perfectly plausible-looking address, which is how
        // (anonymous_namespace)::Delegate at 0x89d708 came out with 48 slots of which all
        // but three were characters -- but it is not 4-aligned, and a real ARM slot is.
        //
        // Judging the word by whether its halves look like characters was tried and is
        // wrong: .text spans 0x100000-0x900000, so the high half of a genuine address sits
        // squarely in the printable range, and roughly one address in 700 would have been
        // thrown away for looking like text.
        if ((value & 1L) == 0 && (value & 3L) != 0) { rejectedAlign++; return false; }

        // Everything below needs the target to have been disassembled, and this scan runs
        // before the pipeline creates its slot functions and before analysis catches up.
        // Asking an undisassembled address what instruction set it is in gets the block's
        // default rather than the truth, and acting on that answer truncated 233 tables --
        // splitting groups, stranding sub-tables, and pushing 34 classes to REAL_WEAK.
        // An unknown answer is not a wrong one, so nothing is rejected on it.
        if (program.getListing().getInstructionAt(target) == null) return true;

        Register tmode = program.getLanguage().getRegister("TMode");
        if (tmode != null) {
            RegisterValue rv = program.getProgramContext().getRegisterValue(tmode, target);
            if (rv != null && rv.hasValue()) {
                boolean targetThumb = rv.getUnsignedValue().intValue() != 0;
                if (targetThumb != ((value & 1L) != 0)) { rejectedMode++; return false; }
            }
        }

        // The "a slot cannot point inside another function" test is deliberately absent.
        // It sounds airtight and is not: measured on ACNL it rejected 224 slots against 2
        // for misalignment and 1 for the thumb bit, and the three tables it was added for
        // are covered by those two. Ghidra's function bodies are a guess -- flow analysis
        // merges neighbours, and a body built from a bad branch swallows the entries after
        // it -- so the test mostly reports that the *body* is wrong, then truncates a
        // perfectly good table on the strength of it. The damage compounds: a truncated
        // table breaks the chain, the group splits, both halves claim the class, and the
        // offcuts produce sub-tables with offset-to-top values like -8508 that then poison
        // the thunk cross-check.
        return true;
    }


    private boolean isFunctionPointer(Address addr, long value) {
        for (Reference ref : program.getReferenceManager().getReferencesFrom(addr)) {
            if (ref instanceof ExternalReference) return true;
        }
        if (isUnrelocatedConstant(addr, value)) { constantsNotSlots++; return false; }
        return isExecutable(value) || isExecutable(value & ~1L);
    }

    /**
     * True when the word at {@code at} is a constant the file itself holds, in a module whose
     * pointers are all written by relocations -- and so cannot be a pointer.
     *
     * <p>A CRO ships every pointer as zero and has the loader write it; a word that is
     * nonzero in the file and still equal to it in memory was never relocated. That matters
     * because a CRO's .text starts at 0x180, so a small integer lands in executable memory:
     * the vbase offset 744 (0x2e8) at the head of ObjectState&lt;AcFsMuRay&gt;'s table in
     * ModuleMusFish points straight at a PLT stub. Taken as a function pointer it became the
     * last slot of the table before it and made classes with nothing in common look like
     * they shared a method; taken as code, it was refused as a vbase offset. In code.bin
     * memory equals the file everywhere, so this never fires there.
     */
    private boolean isUnrelocatedConstant(Address at, long value) {
        if (value == 0 || !relocatedImage()) return false;
        Long file = originalWord(at);
        return file != null && file == value;
    }

    private Boolean relocatedImage;
    private int constantsNotSlots;

    /**
     * Whether this image's read-only data was written by relocations at load: some words
     * differ between memory and the imported file. Measured once, over the read-only blocks.
     */
    private boolean relocatedImage() {
        if (relocatedImage != null) return relocatedImage;
        int differing = 0;
        outer:
        for (MemoryBlock block : readOnlyBlocks()) {
            for (MemoryBlockSourceInfo info : block.getSourceInfos()) {
                if (info.getFileBytes().isEmpty()) continue;
                FileBytes fb = info.getFileBytes().get();
                int len = (int) Math.min(info.getLength(), Integer.MAX_VALUE);
                byte[] mem = new byte[len];
                byte[] file = new byte[len];
                try {
                    memory.getBytes(info.getMinAddress(), mem);
                    fb.getOriginalBytes(info.getFileBytesOffset(), file);
                } catch (Exception e) {
                    continue;
                }
                for (int i = 0; i + PTR_SIZE <= len; i += PTR_SIZE) {
                    if (mem[i] != file[i] || mem[i + 1] != file[i + 1]
                            || mem[i + 2] != file[i + 2] || mem[i + 3] != file[i + 3]) {
                        if (++differing >= MIN_RELOCATED_WORDS) break outer;
                    }
                }
            }
        }
        relocatedImage = differing >= MIN_RELOCATED_WORDS;
        return relocatedImage;
    }

    /** Words that must differ from the file before the image counts as relocated at load. */
    private static final int MIN_RELOCATED_WORDS = 16;

    /** The word the imported file holds at this address, or null when there is none. */
    private Long originalWord(Address at) {
        MemoryBlock block = memory.getBlock(at);
        if (block == null) return null;
        for (MemoryBlockSourceInfo info : block.getSourceInfos()) {
            if (!info.contains(at) || info.getFileBytes().isEmpty()) continue;
            FileBytes fb = info.getFileBytes().get();
            long off = info.getFileBytesOffset(at);
            try {
                long v = 0;
                for (int i = PTR_SIZE - 1; i >= 0; i--) {
                    v = (v << 8) | (fb.getOriginalByte(off + i) & 0xffL);
                }
                return v;
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    private boolean isExecutable(long value) {
        try {
            return isExecutableAddress(space.getAddress(value));
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isExecutableAddress(Address addr) {
        if (addr == null) return false;
        MemoryBlock block = memory.getBlock(addr);
        return block != null && block.isExecute();
    }

    private List<MemoryBlock> readOnlyBlocks() {
        List<MemoryBlock> blocks = new ArrayList<>();
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.getName().equals(".rodata") || block.getName().equals("rodata")) {
                blocks.add(block);
            }
        }
        if (!blocks.isEmpty()) return blocks;
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isInitialized() && block.isRead() && !block.isExecute()) {
                blocks.add(block);
            }
        }
        return blocks;
    }

    private byte[] readBlock(MemoryBlock block) {
        try {
            int size = (int) Math.min(block.getSize(), Integer.MAX_VALUE);
            byte[] bytes = new byte[size];
            int read = block.getBytes(block.getStart(), bytes);
            if (read <= 0) return null;
            return (read == size) ? bytes : Arrays.copyOf(bytes, read);
        } catch (Exception e) {
            return null;
        }
    }

    private long readWord(Address addr) throws Exception {
        return Integer.toUnsignedLong(memory.getInt(addr));
    }

    private long readWord(byte[] b, int i) {
        int v = bigEndian
                ? ((b[i] & 0xff) << 24) | ((b[i + 1] & 0xff) << 16)
                    | ((b[i + 2] & 0xff) << 8) | (b[i + 3] & 0xff)
                : ((b[i + 3] & 0xff) << 24) | ((b[i + 2] & 0xff) << 16)
                    | ((b[i + 1] & 0xff) << 8) | (b[i] & 0xff);
        return Integer.toUnsignedLong(v);
    }

    private boolean cancelled() {
        return monitor != null && monitor.isCancelled();
    }
}
