// DiagnoseVtableGroups.java
// Read-only report on how VtableScan sees this program's vtables.
//
// ARMCC emits construction vtables that carry a base class's typeinfo but belong to some
// deriving class, in plain .constdata sections far from any class vtable. The rename
// pipeline used to swallow them as extra sub-tables of the base. This script shows, per
// candidate table, the evidence VtableScan used to tell the two apart, so the
// classification can be checked against a known-good image before anything downstream
// starts trusting it.
//
// Prompts for a class-name filter; an empty answer reports every class that has more than
// one candidate group, which is where the interesting cases are. Answer "*" for everything.
//
// Writes nothing to the program.
//
// @category RTTI
// @author AlgebraManiacABC

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import util.BaseRef;
import util.VtableScan;
import util.VtableScan.Kind;
import util.VtableScan.SubTable;
import util.VtableScan.VtableGroup;
import util.VtableScan.Vtt;

import java.util.*;

public class DiagnoseVtableGroups extends GhidraScript {

    private static final int PTR_SIZE = 4;

    private final Map<Long, String> typeinfoToClassName = new HashMap<>();
    private final Map<Long, Integer> typeinfoSizes = new HashMap<>();
    private final Map<String, List<BaseRef>> baseInfo = new HashMap<>();

    @Override
    public void run() throws Exception {
        collectTypeinfos();
        if (typeinfoToClassName.isEmpty()) {
            printerr("No typeinfo symbols found. Run ProcessAllRTTI first.");
            return;
        }
        resolveBases();

        println("=== Vtable group diagnosis for " + currentProgram.getName() + " ===");
        println("    typeinfo structs: " + typeinfoToClassName.size());

        VtableScan scan = new VtableScan(currentProgram, typeinfoToClassName, typeinfoSizes,
                baseInfo, this::println, monitor);
        scan.scan();
        scan.printSummary();

        reportConstructionRuns(scan);

        String filter = askFilter();
        report(scan, filter);
    }

    private String askFilter() {
        try {
            return askString("Diagnose vtable groups",
                    "Class name substring ('*' for all, blank for contested classes only)",
                    "");
        } catch (Exception e) {
            return "";   // headless or cancelled
        }
    }

    // ---------------------------------------------------------------
    //  Inputs for VtableScan
    // ---------------------------------------------------------------

    private void collectTypeinfos() {
        SymbolIterator iter = currentProgram.getSymbolTable().getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            if (!sym.getName().equals("typeinfo")) continue;
            Namespace ns = sym.getParentNamespace();
            if (ns == null || ns.isGlobal()) continue;
            String className = ns.getName(true);
            if (className.startsWith("__cxxabiv1")) continue;

            long addr = sym.getAddress().getOffset();
            typeinfoToClassName.putIfAbsent(addr, className);
        }
    }

    /**
     * Read each typeinfo's base array. The applied struct's length says which of the three
     * __cxxabiv1 shapes it is, exactly as ExportClassHierarchy decides it.
     */
    private void resolveBases() throws Exception {
        Memory mem = currentProgram.getMemory();
        for (Map.Entry<Long, String> e : new ArrayList<>(typeinfoToClassName.entrySet())) {
            Address addr = toAddr(e.getKey());
            int size = appliedSize(addr);
            typeinfoSizes.put(e.getKey(), Math.max(size, 8));

            List<BaseRef> bases = new ArrayList<>();
            if (size == 12) {
                // A __si base is always public, non-virtual, at offset 0.
                addBase(bases, mem, addr.add(8), BaseRef.PUBLIC_MASK);
            } else if (size >= 16) {
                int baseCount = mem.getInt(addr.add(12));
                if (baseCount > 0 && baseCount < 1024) {
                    typeinfoSizes.put(e.getKey(), 16 + 8 * baseCount);
                    for (int b = 0; b < baseCount; b++) {
                        Address entry = addr.add(16 + b * 8L);
                        addBase(bases, mem, entry, mem.getInt(entry.add(4)));
                    }
                }
            }
            if (!bases.isEmpty()) baseInfo.put(e.getValue(), bases);
        }
    }

    private void addBase(List<BaseRef> bases, Memory mem, Address field, int offsetFlags) {
        try {
            long ptr = Integer.toUnsignedLong(mem.getInt(field));
            String name = typeinfoToClassName.get(ptr);
            if (name != null) bases.add(new BaseRef(name, offsetFlags));
        } catch (Exception ignored) {
            // an unresolved external base; it cannot contribute a vbase-offset word we
            // could predict anyway
        }
    }

    /** Length of the data applied at a typeinfo, or 0 when nothing useful is applied. */
    private int appliedSize(Address addr) {
        Data data = currentProgram.getListing().getDataAt(addr);
        if (data == null) return 0;
        if (data.getDataType() instanceof Undefined) return 0;
        return data.getLength();
    }

    // ---------------------------------------------------------------
    //  Report
    // ---------------------------------------------------------------

    private void report(VtableScan scan, String filter) {
        Map<String, List<VtableGroup>> byClass = new TreeMap<>();
        for (VtableGroup g : scan.groups()) {
            byClass.computeIfAbsent(g.className(), k -> new ArrayList<>()).add(g);
        }

        boolean contestedOnly = filter.isBlank();
        boolean all = "*".equals(filter);

        int shown = 0;
        for (Map.Entry<String, List<VtableGroup>> e : byClass.entrySet()) {
            if (monitor.isCancelled()) return;
            String className = e.getKey();
            List<VtableGroup> candidates = e.getValue();

            if (!all) {
                if (contestedOnly && candidates.size() < 2) continue;
                if (!contestedOnly && !className.contains(filter)) continue;
            }
            shown++;
            printClass(scan, className, candidates);
        }

        println("");
        println("=== " + shown + " class(es) reported ===");
        if (contestedOnly && shown == 0) {
            println("    No class had more than one candidate group.");
        }
    }

    private void printClass(VtableScan scan, String className, List<VtableGroup> candidates) {
        println("");
        println("--- " + className + " : " + candidates.size() + " candidate group(s) ---");

        for (VtableGroup g : candidates) {
            SubTable p = g.primary();
            println(String.format("  %s  head=%s  point=%s  %d sub-table(s)  %d bytes",
                    g.kind(), p.head(), p.addressPoint(), g.subs().size(),
                    scan.groupLength(g)));

            if (g.derivedOwner() != null) {
                println("    emitted for: " + g.derivedOwner());
            }

            for (int i = 0; i < g.subs().size(); i++) {
                SubTable s = g.subs().get(i);
                StringBuilder sb = new StringBuilder();
                sb.append(String.format("    sub[%d] point=%s  offset_to_top=%d  slots=%d",
                        i, s.addressPoint(), s.offsetToTop(), s.slots().size()));
                if (s.vbaseCount() > 0) {
                    sb.append("  ").append(s.headerKind()).append("_offsets=");
                    for (int v = 0; v < s.vbaseOffsets().length; v++) {
                        if (v > 0) sb.append(",");
                        sb.append(s.vbaseOffsets()[v]);
                    }
                }
                println(sb.toString());
            }

            reportOccurrences(scan, g);
            reportVtts(scan, g);

            if (g.kind() != Kind.REAL && g.kind() != Kind.REAL_WEAK) {
                int same = scan.leadingIdentityBytes(g);
                if (same > 0) {
                    println("    leading bytes identical to the real table: " + same);
                }
            }
            if (!g.evidence().isBlank()) {
                println("    evidence: " + g.evidence());
            }
        }
    }

    private void reportOccurrences(VtableScan scan, VtableGroup g) {
        Address point = g.primary().addressPoint();

        List<Address> loaders = scan.codeLoadersOf(point);
        StringBuilder sb = new StringBuilder();
        sb.append("    code references: ").append(loaders.size());
        for (int i = 0; i < Math.min(3, loaders.size()); i++) {
            sb.append(i == 0 ? "  e.g. " : ", ").append(loaders.get(i));
        }
        println(sb.toString());

        List<Address> where = scan.occurrencesOf(point);
        int inCode = 0;
        for (Address a : where) if (isExecutable(a)) inCode++;
        println("    words holding this point: " + where.size()
                + " (" + inCode + " in executable memory)");
    }

    private void reportVtts(VtableScan scan, VtableGroup g) {
        for (Vtt v : scan.vttsReaching(g)) {
            StringBuilder sb = new StringBuilder();
            sb.append("    reached from VTT at ").append(v.start())
              .append(" (owner ").append(v.ownerClass())
              .append(", ").append(v.entries().size()).append(" entries)");
            if (v.ownerClass().equals(g.className()) && g.vtt() == v) {
                sb.append(" <- its own VTT");
            }
            println(sb.toString());
            for (int i = 0; i < v.entries().size(); i++) {
                Address entry = v.entries().get(i);
                VtableGroup target = scan.groupAtPoint(entry);
                String desc = (target == null) ? "?"
                        : target.className() + " " + target.kind()
                          + " +" + (entry.getOffset() - target.head().getOffset());
                println(String.format("      [%d] %s  %s", i, entry, desc));
            }
        }
    }

    private boolean isExecutable(Address addr) {
        var block = currentProgram.getMemory().getBlock(addr);
        return block != null && block.isExecute();
    }

    // ---------------------------------------------------------------
    //  Construction-vtable runs
    // ---------------------------------------------------------------

    /**
     * Construction vtables land in address-adjacent runs, and a run's length is reported
     * to be twice the depth of the inheritance chain beneath the class that introduced the
     * virtual base (hierarchy_recovery.md section 5, record E2.4-r016). That is a second,
     * entirely independent handle on chain depth: the typeinfo graph derives it from
     * pointers, this derives it from how much const data the compiler emitted.
     *
     * <p>This prints the two side by side and stops there. It deliberately renders no
     * verdict and nothing downstream consumes it -- the exact definition of "depth" the
     * rule uses is not pinned down here, and a disagreement is as likely to mean the rule
     * has been read too narrowly as that the grouping is wrong. Once one image shows the
     * two columns tracking each other, a real check can be built on it; until then a
     * mismatch is a lead, not a fault.
     */
    private void reportConstructionRuns(VtableScan scan) {
        List<VtableGroup> ctor = new ArrayList<>();
        for (VtableGroup g : scan.groups()) {
            if (g.kind() == Kind.CONSTRUCTION) ctor.add(g);
        }
        if (ctor.isEmpty()) return;
        ctor.sort(Comparator.comparing(g -> g.primary().head()));

        println("");
        println("=== construction-vtable runs (" + ctor.size() + " tables) ===");
        println("    run length should be twice the chain depth; both columns are");
        println("    measurements, and neither is used for anything else.");

        int start = 0;
        while (start < ctor.size()) {
            int end = start + 1;
            while (end < ctor.size() && adjacent(scan, ctor.get(end - 1), ctor.get(end))) end++;

            List<VtableGroup> run = ctor.subList(start, end);
            Set<String> owners = new LinkedHashSet<>();
            for (VtableGroup g : run) {
                owners.add(g.derivedOwner() == null ? "?" : g.derivedOwner());
            }
            int deepest = 0;
            for (String owner : owners) deepest = Math.max(deepest, chainDepth(owner));

            println(String.format("  %s..%s  %d table(s) -> depth %d;  graph depth %d  [%s]",
                    run.get(0).primary().head(),
                    lastSub(run.get(run.size() - 1)).end(),
                    run.size(), run.size() / 2, deepest,
                    String.join(", ", owners)));
            start = end;
        }
    }

    private static SubTable lastSub(VtableGroup g) {
        return g.subs().get(g.subs().size() - 1);
    }

    /** True when {@code b} starts where {@code a} ends, allowing one word of padding. */
    private boolean adjacent(VtableScan scan, VtableGroup a, VtableGroup b) {
        long gap = b.primary().head().getOffset() - lastSub(a).end().getOffset();
        return gap >= 0 && gap <= PTR_SIZE;
    }

    /** Longest path from {@code className} up to a root, counting the class itself. */
    private int chainDepth(String className) {
        return chainDepth(className, new HashSet<>());
    }

    private int chainDepth(String className, Set<String> onPath) {
        if (className == null || !onPath.add(className)) return 0;
        try {
            int best = 0;
            for (BaseRef b : baseInfo.getOrDefault(className, List.of())) {
                best = Math.max(best, chainDepth(b.name(), onPath));
            }
            return best + 1;
        } finally {
            onPath.remove(className);
        }
    }
}
