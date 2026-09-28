// DiagnoseVtableWriters.java
//
// TEMPORARY DEBUG SCRIPT - delete when the destructor-naming question is settled.
//
// Answers one question: for a given class, why did RenameVTableFunctions fail to
// see that a vtable slot writes its own vtable pointer?
//
// It reproduces the two checks that util.RenameVTableFunctions.writesOwnVtable
// makes, separately and with their inputs shown:
//
//   writers      = references to the class's vtable address points, plus one hop
//                  back for the ARM literal pool (ownVtableWriters)
//   body test    = func.getBody().contains(writer)
//   scan test    = walk instructions from the entry to the next function entry
//
// so a slot that a human can see writes its vtable, but the renamer named F<nn>,
// shows which of the two failed and why: no references recorded at all, a body
// that stops short, a writer sitting outside the scanned range, and so on.
//
// Read-only: opens no transaction and changes nothing.
//
// @category RTTI
// @author AlgebraManiacABC

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class DiagnoseVtableWriters extends GhidraScript {

    private static final int PTR_SIZE = 4;
    private static final int MAX_BODY_SCAN = 2048;

    private SymbolTable symTab;
    private ReferenceManager refMgr;
    private Listing listing;
    private AddressSpace space;

    @Override
    protected void run() throws Exception {
        symTab = currentProgram.getSymbolTable();
        refMgr = currentProgram.getReferenceManager();
        listing = currentProgram.getListing();
        space = currentProgram.getMinAddress().getAddressSpace();

        String className = askClassName();
        if (className == null) return;

        Namespace ns = findClassNamespace(className);
        if (ns == null) {
            printerr("No class namespace named \"" + className + "\" in " +
                    currentProgram.getName());
            return;
        }

        println("=== " + ns.getName(true) + " in " + currentProgram.getName() + " ===");

        List<Address> points = vtableAddressPoints(ns);
        if (points.isEmpty()) {
            println("NO vtable address points. ownVtableWriters would return an empty set,");
            println("so writesOwnVtable returns false for every slot before any test runs.");
            println("(The renamer labels only primary vtables, so a secondary one shows up");
            println(" here only if something else labelled it.)");
        }
        for (Address point : points) {
            println("  vtable address point: " + point);
        }

        Set<String> ancestors = ancestorsOf(ns);
        println("  ancestors (by RTTI base pointers): " +
                (ancestors.isEmpty() ? "(none found)" : String.join(", ", ancestors)));

        Set<Address> writers = collectWriters(points);
        reportWriters(points, writers);

        for (Address point : points) {
            println("");
            println("--- slots at " + point + " ---");
            reportSlots(point, writers, ancestors);
        }

        // The inherited destructor index comes from the first parent, so its own slot
        // naming decides where this class fills one in when it detects nothing.
        for (String ancestor : ancestors) {
            Namespace ancestorNs = findClassNamespace(ancestor);
            if (ancestorNs == null) continue;
            List<Address> ancestorPoints = vtableAddressPoints(ancestorNs);
            Set<Address> ancestorWriters = collectWriters(ancestorPoints);
            Set<String> above = ancestorsOf(ancestorNs);
            for (Address point : ancestorPoints) {
                println("");
                println("--- ANCESTOR " + ancestor + ", slots at " + point + " ---");
                reportSlots(point, ancestorWriters, above);
            }
        }
    }

    // ------------------------------------------------------------------ inputs

    private String askClassName() throws Exception {
        String suggested = "";
        if (currentAddress != null) {
            Symbol sym = symTab.getPrimarySymbol(currentAddress);
            if (sym != null) {
                Namespace ns = sym.getParentNamespace();
                if (ns != null && !ns.isGlobal()) suggested = ns.getName(true);
            }
        }
        try {
            return askString("Diagnose vtable writers",
                    "Fully qualified class name (e.g. ComButton1Lyt)", suggested);
        } catch (Exception cancelled) {
            return null;
        }
    }

    private Namespace findClassNamespace(String className) {
        SymbolIterator iter = symTab.getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            Namespace ns = sym.getParentNamespace();
            if (ns == null || ns.isGlobal()) continue;
            if (ns.getName(true).equals(className)) return ns;
        }
        return null;
    }

    // ------------------------------------------------------------------ vtables

    /**
     * Labelled vtable address points in this class's namespace.
     *
     * <p>The "vtable" label marks the head, which is <em>not</em> a fixed distance from
     * the address point: a class with virtual bases carries one offset word per virtual
     * base in front of offset-to-top. So rather than adding two words, walk forward to
     * the typeinfo pointer -- the first word holding the address of a known typeinfo --
     * and take the word after it. That relationship always holds.
     */
    private List<Address> vtableAddressPoints(Namespace ns) {
        List<Address> points = new ArrayList<>();
        SymbolIterator iter = symTab.getSymbols(ns);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            if (!sym.getName().equals("vtable")) continue;
            Address point = addressPointFrom(sym.getAddress());
            if (point != null) points.add(point);
        }
        points.sort(null);
        return points;
    }

    /** Longest header we will walk past looking for the typeinfo pointer. */
    private static final int MAX_HEADER_WORDS = 20;

    private Address addressPointFrom(Address head) {
        for (int i = 0; i < MAX_HEADER_WORDS; i++) {
            try {
                Address at = head.add((long) PTR_SIZE * i);
                long value = Integer.toUnsignedLong(currentProgram.getMemory().getInt(at));
                if (isTypeinfo(value)) return at.add(PTR_SIZE);
            } catch (Exception e) {
                return null;
            }
        }
        return null;
    }

    /** Whether a word points at something carrying a "typeinfo" symbol. */
    private boolean isTypeinfo(long value) {
        if (value == 0) return false;
        try {
            Address target = currentProgram.getMinAddress().getAddressSpace()
                    .getAddress(value);
            for (Symbol s : symTab.getSymbols(target)) {
                if (s.getName().equals("typeinfo")) return true;
            }
        } catch (Exception e) { /* not an address in this program */ }
        return false;
    }

    /** ownVtableWriters: references to each point, plus one hop back for the pool. */
    private Set<Address> collectWriters(List<Address> points) {
        Set<Address> writers = new LinkedHashSet<>();
        for (Address point : points) {
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

    private void reportWriters(List<Address> points, Set<Address> writers) {
        println("");
        println("--- writers (refs to the address points, + one hop back) ---");
        if (writers.isEmpty() && !points.isEmpty()) {
            println("  NONE. Nothing in the program references these address points, so no");
            println("  slot can ever pass writesOwnVtable. If the code visibly stores the");
            println("  vtable pointer, the literal holding it carries no reference: check");
            println("  whether that word is typed as a pointer.");
            return;
        }
        for (Address w : writers) {
            Function owner = listing.getFunctionContaining(w);
            String where = (owner == null) ? "not inside any function"
                    : owner.getName(true) + " entry=" + owner.getEntryPoint() +
                      " body=" + owner.getBody().getNumAddresses() + " bytes";
            String what = (listing.getInstructionAt(w) != null) ? "instruction" : "data";
            println("  " + w + "  (" + what + ")  " + where);
        }
    }

    // ------------------------------------------------------------------ slots

    private void reportSlots(Address point, Set<Address> writers, Set<String> ancestors) {
        Address slotAddr = point;
        for (int i = 0; i < 64; i++) {
            long value;
            try {
                value = Integer.toUnsignedLong(getInt(slotAddr));
            } catch (Exception e) {
                return;
            }
            if (!isFunctionPointer(slotAddr, value)) return;

            Address funcAddr = space.getAddress(value & ~1L);
            Function func = listing.getFunctionAt(funcAddr);

            StringBuilder line = new StringBuilder();
            line.append(String.format("slot %-2d @ %s -> %s", i, slotAddr, funcAddr));
            if (func != null) {
                line.append("  ").append(func.getName(true));
                long body = func.getBody().getNumAddresses();
                line.append("  body=").append(body).append(body <= 1 ? " bytes <-- SHORT" : " bytes");
            } else {
                line.append("  (no function here)");
            }
            println(line.toString());

            if (func != null) {
                reportSymbols(funcAddr);
                reportPureVirtual(slotAddr, value);
                diagnoseSlot(func, funcAddr, writers, ancestors);
            }
            slotAddr = slotAddr.add(PTR_SIZE);
        }
    }

    /**
     * Every symbol on the slot target. createLabel adds a name rather than replacing
     * one, so a function renamed across runs carries all of them and the listing shows
     * whichever is primary -- which may be a stale name from an earlier run rather
     * than what the last run decided.
     */
    private void reportSymbols(Address funcAddr) {
        Symbol[] syms = symTab.getSymbols(funcAddr);
        if (syms.length == 0) {
            println("      symbols: none");
            return;
        }
        println("      symbols: " + syms.length + (syms.length > 1 ? "  <-- MULTIPLE" : ""));
        for (Symbol sym : syms) {
            Namespace owner = sym.getParentNamespace();
            println("        " + (sym.isPrimary() ? "* " : "  ") + sym.getName(true) +
                    "   [" + sym.getSource() + ", ns=" +
                    (owner == null ? "?" : owner.getName(true)) + "]");
        }
        println("        (* = primary, i.e. what the listing and decompiler show)");
    }

    /**
     * Whether this slot would be skipped as a pure-virtual reference before any
     * destructor test runs -- the one path that leaves a slot unnamed even though its
     * function passes every check.
     */
    private void reportPureVirtual(Address slotAddr, long value) {
        Address pv = findPureVirtual();
        if (pv == null) {
            for (Reference ref : refMgr.getReferencesFrom(slotAddr)) {
                if (ref.isExternalReference()) {
                    println("      pure-virtual skip: slot has an external reference; the" +
                            " renamer skips it when __cxa_pure_virtual is external");
                    return;
                }
            }
            println("      pure-virtual skip: no __cxa_pure_virtual symbol in this program");
            return;
        }
        boolean matches = (value & ~1L) == (pv.getOffset() & ~1L);
        println("      pure-virtual skip: " + (matches
                ? "YES - slot value matches __cxa_pure_virtual at " + pv
                : "no (__cxa_pure_virtual at " + pv + ")"));
    }

    private Address findPureVirtual() {
        for (Symbol sym : symTab.getGlobalSymbols("__cxa_pure_virtual")) {
            return sym.getAddress();
        }
        SymbolIterator iter = symTab.getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            if (sym.getName().contains("cxa_pure_virtual")) return sym.getAddress();
        }
        return null;
    }

    private void diagnoseSlot(Function func, Address funcAddr,
                              Set<Address> writers, Set<String> ancestors) {
        // Test 1, as writesOwnVtable does it first.
        Address bodyHit = null;
        for (Address w : writers) {
            if (func.getBody().contains(w)) { bodyHit = w; break; }
        }

        // Test 2, the body-independent scan.
        Address limit = scanLimit(funcAddr);
        Address scanHit = null;
        int scanned = 0;
        Instruction inst = listing.getInstructionAt(funcAddr);
        for (; inst != null && scanned < MAX_BODY_SCAN; scanned++) {
            Address addr = inst.getAddress();
            if (limit != null && addr.compareTo(limit) >= 0) break;
            if (writers.contains(addr)) { scanHit = addr; break; }
            inst = listing.getInstructionAfter(addr);
        }

        // Which writers lie in the function's address range at all, body aside.
        List<Address> inRange = new ArrayList<>();
        for (Address w : writers) {
            if (w.compareTo(funcAddr) >= 0 && (limit == null || w.compareTo(limit) < 0)) {
                inRange.add(w);
            }
        }

        println("      body test: " + (bodyHit != null ? "HIT at " + bodyHit : "miss"));
        println("      scan test: " + (scanHit != null ? "HIT at " + scanHit
                : "miss (" + scanned + " instructions, limit " + limit + ")"));
        println("      writers between entry and limit: " +
                (inRange.isEmpty() ? "none" : inRange.toString()));
        if (bodyHit == null && scanHit == null && !inRange.isEmpty()) {
            println("      ^ writers are in range but neither test saw them: the addresses");
            println("        are data (a literal pool word), not instruction starts.");
        }

        String baseDtor = callsAncestorDestructor(funcAddr, limit, ancestors);
        println("      ancestor destructor call: " + (baseDtor != null ? baseDtor : "none"));

        long body = func.getBody().getNumAddresses();
        println("      thunk-sized (<= 32 bytes): " + (body <= 32 ? "yes" : "no"));
        String del = callsOperatorDelete(funcAddr, limit);
        println("      calls operator delete: " + (del != null ? del : "no"));
        println("      => rule chain would say: " + ruleChain(bodyHit, scanHit, del, baseDtor));
    }

    /** Which name the detection chain would hand this slot, in its real order. */
    private String ruleChain(Address bodyHit, Address scanHit, String del, String baseDtor) {
        if (bodyHit != null || scanHit != null) return "D1 (vtable write)";
        if (del != null) return "D0 (operator delete)";
        if (baseDtor != null) return "D1 (ancestor destructor call)";
        return "nothing - slot stays F<nn> unless a pair rule fills it in";
    }

    /** callsOperatorDelete, one level, without the thunk hand-off. */
    private String callsOperatorDelete(Address funcAddr, Address limit) {
        Instruction inst = listing.getInstructionAt(funcAddr);
        for (int seen = 0; inst != null && seen < MAX_BODY_SCAN; seen++) {
            Address addr = inst.getAddress();
            if (limit != null && addr.compareTo(limit) >= 0) break;
            for (Reference ref : inst.getReferencesFrom()) {
                Address target = ref.getToAddress();
                if (target == null) continue;
                for (Symbol sym : symTab.getSymbols(target)) {
                    String name = sym.getName();
                    if (name.startsWith("operator.delete") || name.startsWith("_Zdl")
                            || name.startsWith("_Zda") || name.equals("D0")
                            || name.startsWith("D0_")) {
                        return sym.getName(true) + " at " + addr;
                    }
                }
            }
            inst = listing.getInstructionAfter(addr);
        }
        return null;
    }

    private Address scanLimit(Address funcAddr) {
        try {
            FunctionIterator after = listing.getFunctions(funcAddr.add(1), true);
            if (after.hasNext()) return after.next().getEntryPoint();
        } catch (Exception e) {
            // end of the address space
        }
        return null;
    }

    private String callsAncestorDestructor(Address funcAddr, Address limit,
                                           Set<String> ancestors) {
        if (ancestors.isEmpty()) return null;
        Instruction inst = listing.getInstructionAt(funcAddr);
        for (int seen = 0; inst != null && seen < MAX_BODY_SCAN; seen++) {
            Address addr = inst.getAddress();
            if (limit != null && addr.compareTo(limit) >= 0) break;
            for (Reference ref : inst.getReferencesFrom()) {
                Address target = ref.getToAddress();
                if (target == null) continue;
                for (Symbol sym : symTab.getSymbols(target)) {
                    String name = sym.getName();
                    if (!(name.equals("D1") || name.startsWith("D1_") || name.endsWith("D1Ev"))) {
                        continue;
                    }
                    Namespace owner = sym.getParentNamespace();
                    if (owner != null && ancestors.contains(owner.getName(true))) {
                        return sym.getName(true) + " at " + addr;
                    }
                }
            }
            inst = listing.getInstructionAfter(addr);
        }
        return null;
    }

    // ------------------------------------------------------------------ RTTI

    /** Ancestors read straight from the typeinfo structs, as the renamer does. */
    private Set<String> ancestorsOf(Namespace ns) {
        Set<String> ancestors = new LinkedHashSet<>();
        Deque<Namespace> queue = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        queue.add(ns);
        seen.add(ns.getName(true));

        while (!queue.isEmpty()) {
            for (String parent : directBases(queue.poll())) {
                if (!ancestors.add(parent)) continue;
                Namespace parentNs = findClassNamespace(parent);
                if (parentNs != null && seen.add(parent)) queue.add(parentNs);
            }
        }
        return ancestors;
    }

    private List<String> directBases(Namespace ns) {
        List<String> bases = new ArrayList<>();
        Address ti = null;
        SymbolIterator iter = symTab.getSymbols(ns);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            if (sym.getName().equals("typeinfo")) { ti = sym.getAddress(); break; }
        }
        if (ti == null) return bases;

        try {
            int len = (listing.getDataAt(ti) != null) ? listing.getDataAt(ti).getLength() : 0;
            if (len == 12) {
                addBase(bases, Integer.toUnsignedLong(getInt(ti.add(8))));
            } else if (len >= 16) {
                int count = getInt(ti.add(12));
                for (int b = 0; b < count && b < 64; b++) {
                    addBase(bases, Integer.toUnsignedLong(getInt(ti.add(16 + b * 8L))));
                }
            }
        } catch (Exception e) {
            // unreadable typeinfo; report what was found so far
        }
        return bases;
    }

    private void addBase(List<String> bases, long typeinfoPtr) {
        if (typeinfoPtr == 0) return;
        try {
            for (Symbol sym : symTab.getSymbols(space.getAddress(typeinfoPtr))) {
                if (!sym.getName().equals("typeinfo")) continue;
                Namespace owner = sym.getParentNamespace();
                if (owner != null && !owner.isGlobal()) bases.add(owner.getName(true));
            }
        } catch (Exception e) {
            // pointer into another module; the renamer resolves those, this does not
        }
    }

    private boolean isFunctionPointer(Address addr, long value) {
        for (Reference ref : refMgr.getReferencesFrom(addr)) {
            if (ref.isExternalReference()) return true;
        }
        return isExecutable(value) || isExecutable(value & ~1L);
    }

    private boolean isExecutable(long value) {
        try {
            MemoryBlock block = currentProgram.getMemory().getBlock(space.getAddress(value));
            return block != null && block.isExecute();
        } catch (Exception e) {
            return false;
        }
    }
}
