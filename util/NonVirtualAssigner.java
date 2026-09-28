// Finds a class's non-virtual member functions by exploiting the link order, and renames
// every member so the names sort the way the functions are actually laid out.
//
//   NonVirtualAssigner assigner = new NonVirtualAssigner(this);
//   assigner.run(program);
//
// Run after ProcessAllRTTI: this pass reads the symbol table rather than re-deriving
// RTTI, so the two stay decoupled.
//
// The premise is that these binaries come from -ffunction-sections objects whose input
// sections the linker sorted by name, so a function's address is decided by the byte-wise
// sort order of its mangled name. Every member of class X shares the literal prefix _ZN1X,
// so X's non-const members occupy one unbroken run of addresses, and anything between two
// known virtuals of X is also a member of X.
//
// Names are fixed width -- M007V003 -- which makes the mangled length prefix a constant
// that cancels out of the comparison, leaving the rank to decide the order outright. See
// memberName() for the layout and why each field sits where it does.
//
// @category RTTI
// @author Claude (for AlgebraManiacABC)

package util;

import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NonVirtualAssigner {

    /** VF03 and friends: what RenameVTableFunctions writes, and this pass's input. */
    private static final Pattern VFUNC = Pattern.compile("V?F(\\d{2,})(?:_(\\d+))?");
    /** The real ABI destructor names, which are never renamed. */
    private static final Pattern DTOR = Pattern.compile("D([01])(?:_(\\d+))?");
    /**
     * This pass's own output, so a re-run can read back the slot it encoded and re-rank
     * from scratch. Without this an M name reads as a real one, and the second run is a
     * silent no-op.
     */
    private static final Pattern MEMBER =
            Pattern.compile("M(\\d{3})(?:V(\\d{3})|N([a-z]{3}))");

    /** See memberName(). */
    private static final String VIRTUAL_FORMAT = "M%03dV%03d";
    private static final String NONVIRTUAL_FORMAT = "M%03dN%s";
    /** Widest rank and slot the three-digit numeric fields hold. */
    private static final int MAX_FIELD = 999;
    /** Non-virtuals per class, aaa through zzz. */
    private static final int MAX_SEQUENCE = 26 * 26 * 26 - 1;

    /**
     * At or below this a function is a tail-call stub rather than a member: a bare branch,
     * or one of the "mov r0, r0" / "copy this, this" shapes with its branch. Well under the
     * 32 bytes RenameVTableFunctions allows an adjustor thunk, which is a real member.
     */
    private static final int STUB_MAX_BYTES = 12;
    /** "A single or a few" stubs in one gap. Past this the gap is a boundary after all. */
    private static final int MAX_TRANSPARENT_STUBS = 8;

    /** One ARM word, and the size of a literal pool entry. */
    private static final int WORD_BYTES = 4;
    /** Below this a stretch of uncovered bytes is alignment slack, not a function. */
    private static final int MIN_GAP_FUNCTION_BYTES = 4;

    private final GhidraScript script;

    private Program program;
    private SymbolTable symTab;

    // Report totals
    private int classesSeen = 0;
    private int runsSeen = 0;
    private int gapsClaimed = 0;
    private int slotsRenamed = 0;
    private int mangledEmitted = 0;
    private int thunksClaimed = 0;
    private int stubsStepped = 0;
    private int stubsDetached = 0;
    private int materialised = 0;
    private int literalWordsSkipped = 0;
    private int dataHeadsRefused = 0;
    private int holesFilled = 0;
    private int vtableFieldsUpdated = 0;
    private int runBreaks = 0;
    private int candidatesDropped = 0;
    private int fragmentsSkipped = 0;
    private int ctorCandidates = 0;
    private int fixedMembers = 0;
    private long uncoveredBytes = 0;
    private final List<String> overflows = new ArrayList<>();
    private final List<String> dtorTailFailures = new ArrayList<>();
    private final List<String> ctorCandidateLines = new ArrayList<>();
    private int dtorTailOk = 0;

    public NonVirtualAssigner(GhidraScript script) {
        this.script = script;
    }

    // ---------------------------------------------------------------
    //  The name
    // ---------------------------------------------------------------

    /**
     * The placeholder for one member: {@code M007V003} is the 7th function of its class in
     * address order, virtual, filling vtable slot 3. A non-virtual reads {@code M008Nacd},
     * where the letters count the class's non-virtuals rather than padding out a slot
     * number it does not have.
     *
     * <pre>
     *   M 007 V 003        M 008 N acd
     *   │  │  │  └── slot  │  │  │  └── which non-virtual of this class, aaa..zzz
     *   │  │  └───── V     │  │  └───── N
     *   │  └──────── rank  │  └──────── rank
     *   └─────────── constant, and required: an Itanium identifier cannot start with a
     *                digit, which isPlainIdentifier in RenameVTableFunctions enforces
     * </pre>
     *
     * Both forms are eight characters. They have to be: fixed width is what makes the
     * length prefix a constant, so the kind field keeps its letter even though the letters
     * after it already imply the answer.
     *
     * Every field is fixed width, which is the whole point. Inside a class the shared
     * _ZN&lt;len&gt;&lt;Class&gt; prefix cancels and the comparison lands on
     * &lt;len&gt;&lt;name&gt;; with every name the same length that prefix is a constant
     * too, so the comparison falls through to the body. There it meets the rank, which was
     * assigned in address order -- so sort order is address order by construction, and no
     * field after the rank can perturb it. Kind and slot ride along as free payload.
     *
     * The destructor anchor survives: '8' (the length prefix) is below 'C' and 'D', so
     * these still sort ahead of C1/C2/D0/D1 exactly as the padded names did.
     *
     * Three digits each, against a worst observed 166 members in a class and slot 191.
     */
    private static String memberName(int rank, boolean virtual, int slot, int sequence) {
        return virtual
                ? String.format(VIRTUAL_FORMAT, rank, slot)
                : String.format(NONVIRTUAL_FORMAT, rank, letters(sequence));
    }

    /** A count as three lowercase letters, aaa, aab, ... zzz. */
    private static String letters(int sequence) {
        char[] out = new char[3];
        for (int i = out.length - 1; i >= 0; i--) {
            out[i] = (char) ('a' + sequence % 26);
            sequence /= 26;
        }
        return new String(out);
    }

    /** Per class: the next rank, and the next non-virtual letter triple. */
    private static final class Counters {
        int rank;
        int nonVirtual;
    }

    // ---------------------------------------------------------------
    //  Members and runs
    // ---------------------------------------------------------------

    private static final class Entry {
        final Function func;
        final Address addr;
        /** Vtable slot index, or -1 for a function claimed out of a gap. */
        final int slot;
        /** D0/D1, or a real name: a fixed point that takes no rank and is never renamed. */
        final boolean fixed;
        /** Claimed from a gap, so it still needs a namespace and a calling convention. */
        final boolean claimed;
        final String dtorKind;
        String name;

        Entry(Function func, int slot, boolean fixed, boolean claimed, String dtorKind) {
            this.func = func;
            this.addr = func.getEntryPoint();
            this.slot = slot;
            this.fixed = fixed;
            this.claimed = claimed;
            this.dtorKind = dtorKind;
        }

        boolean virtual() { return slot >= 0; }
    }

    /** A maximal stretch of one class's functions with nothing foreign inside it. */
    private static final class Run {
        final List<Entry> entries = new ArrayList<>();
    }

    /** Everything read off the program in one go, and invalidated by any change to it. */
    private static final class Scan {
        final List<Function> all = new ArrayList<>();
        final Map<Namespace, List<Run>> runs = new LinkedHashMap<>();
        /** Per class, the {before, after} function indices bounding each unbroken gap. */
        final Map<Namespace, List<int[]>> gaps = new LinkedHashMap<>();
        /** Per class, whether its code is Thumb. Null where nothing said. */
        final Map<Namespace, Boolean> thumb = new LinkedHashMap<>();
    }

    public void run(Program prog) {
        program = prog;
        symTab = prog.getSymbolTable();

        script.printf("=== Non-virtual assignment for %s ===\n", program.getName());

        Scan scan = scan();

        // Before anything reasons about gaps: recover the code Ghidra stopped short of
        // inside the functions themselves. It is what creates the references that say
        // which bytes behind a function are its literal pool, so it has to happen first
        // or materialise below is deciding blind.
        int filled = fillCodeHoles(scan);
        if (filled > 0) {
            script.printf("    Disassembled %d holes inside function bodies; running " +
                    "analysis so the references they make exist before gaps are read\n",
                    filled);
            script.analyzeChanges(program);
            scan = scan();
        }

        // Bytes inside a gap that no function covers are this class's code by the same
        // argument that claims the functions around them, so they are worth disassembling
        // -- in the class's own instruction set, which its existing members already settle.
        int created = materialise(scan);
        if (created > 0) {
            script.printf("    Disassembled %d functions out of gap bytes; running " +
                    "analysis so their references exist before naming\n", created);
            script.analyzeChanges(program);
            // Everything read above predates these functions.
            scan = scan();
        }

        for (Map.Entry<Namespace, List<Run>> entry : scan.runs.entrySet()) {
            classesSeen++;
            Namespace ns = entry.getKey();
            List<Run> runs = entry.getValue();

            // One rank counter for the whole class, never reset. Order only has to hold
            // within a run -- each section sorts on its own -- but letting the counter run
            // on across runs costs nothing and makes every name in the class unique for
            // free, which is what a per-run counter could not do.
            Counters counters = new Counters();
            for (Run run : runs) {
                runsSeen++;
                checkDestructorTail(ns, run);
                setAsideConstructorCandidates(ns, run);
                assign(ns, run, counters);
                apply(ns, run);
            }
        }

        report();
    }

    /** Read every class's members, runs and gaps off the program as it stands. */
    private Scan scan() {
        runBreaks = 0;
        candidatesDropped = 0;
        fragmentsSkipped = 0;
        fixedMembers = 0;
        uncoveredBytes = 0;
        stubsStepped = 0;
        stubsDetached = 0;

        Scan scan = new Scan();
        FunctionIterator iter = program.getListing().getFunctions(true);
        while (iter.hasNext()) scan.all.add(iter.next());

        // Class namespace -> positions of its members in the address-ordered list.
        Map<Namespace, List<Integer>> members = new LinkedHashMap<>();
        for (int i = 0; i < scan.all.size(); i++) {
            Symbol sym = scan.all.get(i).getSymbol();
            if (sym == null) continue;
            Namespace ns = sym.getParentNamespace();
            if (!(ns instanceof GhidraClass)) continue;
            // A suffixed placeholder is an adjustor thunk. It mangles _ZTh..., which sits
            // in a different sort neighbourhood entirely, so it is not part of this run.
            if (subIndex(sym.getName()) > 0) continue;
            members.computeIfAbsent(ns, k -> new ArrayList<>()).add(i);
        }

        for (Map.Entry<Namespace, List<Integer>> entry : members.entrySet()) {
            Namespace ns = entry.getKey();
            List<int[]> gaps = new ArrayList<>();
            scan.runs.put(ns, splitRuns(scan.all, ns, entry.getValue(), gaps));
            scan.gaps.put(ns, gaps);
            scan.thumb.put(ns, classThumb(scan.all, entry.getValue()));
        }
        return scan;
    }

    /**
     * Cut a class's members into runs. Anything foreign between two of them proves the run
     * ended there -- the class was split across output sections, or into the separate
     * lexicographic cluster its const members form. Everything else in the gap is a
     * non-virtual member of the class, branch thunks included.
     */
    private List<Run> splitRuns(List<Function> all, Namespace ns, List<Integer> positions,
                                List<int[]> gapsOut) {
        List<Run> runs = new ArrayList<>();
        Run current = new Run();
        current.entries.add(toEntry(all.get(positions.get(0)), false));

        for (int p = 1; p < positions.size(); p++) {
            int prev = positions.get(p - 1);
            int here = positions.get(p);

            List<Function> candidates = new ArrayList<>();
            boolean broke = false;
            int stubs = 0;
            for (int k = prev + 1; k < here; k++) {
                Function gap = all.get(k);

                // A single or a few tail-call stubs between two members is not a section
                // boundary. The linker drops a veneer where the call site can reach it, not
                // where the sort would put it, so veneer tables interleave classes at a
                // four-byte stride. Breaking the run on one no longer misorders anything --
                // the rank counter runs on across runs -- but it still throws away every
                // candidate in the gap and stops materialise from looking at it. Step over
                // it instead, and claim it only if it is not another class's.
                // A piece of the function before it, not a function. Naming it hands the
                // class a second member that is really the middle of the first one, which
                // is where the checker's 17 duplicated names come from.
                if (isFragment(gap)) { fragmentsSkipped++; continue; }

                if (isTrivialStub(gap)) {
                    if (++stubs > MAX_TRANSPARENT_STUBS) { broke = true; break; }
                    stubsStepped++;
                    // Ask whose it is before detaching. A thunk reports its target's name
                    // and namespace, so detaching first would strip a foreign veneer of the
                    // only evidence it belongs to another class and let this one claim it.
                    boolean foreign = isForeign(gap, ns);
                    unthunk(gap);
                    if (!foreign) candidates.add(gap);
                    continue;
                }

                if (isForeign(gap, ns)) { broke = true; break; }
                candidates.add(gap);
            }
            uncoveredBytes += uncovered(all, prev, here);

            if (broke) {
                // The run ended somewhere at or before the foreign symbol, and nothing
                // says where, so the whole gap goes rather than half of it.
                runBreaks++;
                candidatesDropped += candidates.size();
                runs.add(current);
                current = new Run();
            } else {
                gapsOut.add(new int[]{prev, here});
                for (Function claimed : candidates) {
                    current.entries.add(toEntry(claimed, true));
                }
            }
            current.entries.add(toEntry(all.get(here), false));
        }

        runs.add(current);
        return runs;
    }

    private Entry toEntry(Function func, boolean claimed) {
        if (claimed) return new Entry(func, -1, false, true, null);

        // Every symbol here, not just the primary one: after ToggleMangledNames the
        // mangled spelling is primary and the placeholder is a plain label beside it.
        for (Symbol sym : symTab.getSymbols(func.getEntryPoint())) {
            String name = sym.getName();

            Matcher dtor = DTOR.matcher(name);
            if (dtor.matches()) return new Entry(func, -1, true, false, "D" + dtor.group(1));

            // What RenameVTableFunctions wrote.
            Matcher vf = VFUNC.matcher(name);
            if (vf.matches()) {
                return new Entry(func, Integer.parseInt(vf.group(1)), false, false, null);
            }

            // What a previous run of this pass wrote. The slot comes back out of the name,
            // which is the point of having put it there, and the rank is discarded -- this
            // run works out its own.
            Matcher member = MEMBER.matcher(name);
            if (member.matches()) {
                int slot = (member.group(2) == null) ? -1 : Integer.parseInt(member.group(2));
                return new Entry(func, slot, false, false, null);
            }
        }

        // An imported or hand-written name. Real, so it stands, and its true sort position
        // is whatever its real mangling says -- which this pass cannot compute.
        fixedMembers++;
        return new Entry(func, -1, true, false, null);
    }

    /** The symbol a rename should land on: never the mangled spelling beside it. */
    private Symbol placeholderSymbol(Function func) {
        Symbol primary = func.getSymbol();
        if (primary != null && !primary.getName().startsWith("_Z")) return primary;
        for (Symbol sym : symTab.getSymbols(func.getEntryPoint())) {
            if (!sym.getName().startsWith("_Z")) return sym;
        }
        return primary;
    }

    /** The sub-vtable index of a suffixed placeholder such as VF05_2 or D1_1, else -1. */
    private static int subIndex(String name) {
        Matcher vf = VFUNC.matcher(name);
        if (vf.matches() && vf.group(2) != null) return Integer.parseInt(vf.group(2));
        Matcher dtor = DTOR.matcher(name);
        if (dtor.matches() && dtor.group(2) != null) return Integer.parseInt(dtor.group(2));
        return -1;
    }

    /**
     * Whether this function carries a name that cannot belong to the class whose run we are
     * walking: another class's member, or a real global symbol. Ghidra's defaults and this
     * pipeline's own placeholders and mangled labels do not count.
     */
    /**
     * A Ghidra function that is really a branch target inside the function before it.
     *
     * <p>Ghidra splits one out wherever a conditional branch lands on an address it decides
     * to treat as an entry -- {@code 0x586104} is a {@code beq} target inside
     * {@code 0x5860c0}, and {@code 0x4f8f3c} is loop code. Both start with the {@code NOP}
     * {@code --branchnop} leaves behind (open answers Q6b), which is what makes them look
     * like entries in the first place.
     *
     * <p>The test is conservative on purpose: every reference to the address has to come
     * from inside the function it sits in the middle of. One data reference -- a vtable
     * slot, a function pointer, a jump table -- means something outside treats it as an
     * entry point, and then it is one.
     */
    private boolean isFragment(Function func) {
        Address entry = func.getEntryPoint();
        if (entry.getOffset() == 0) return false;
        Function prev;
        try {
            prev = program.getListing().getFunctionContaining(entry.subtract(1));
        } catch (Exception e) {
            return false;
        }
        if (prev == null || prev.equals(func)) return false;

        boolean reached = false;
        for (Reference ref : program.getReferenceManager().getReferencesTo(entry)) {
            if (!ref.getReferenceType().isFlow()) return false;      // data: a real entry
            if (!prev.getBody().contains(ref.getFromAddress())) return false;
            reached = true;
        }
        return reached;
    }

    private boolean isForeign(Function func, Namespace ns) {
        for (Symbol sym : symTab.getSymbols(func.getEntryPoint())) {
            // A dynamic name is Ghidra's guess, never evidence of anything. A thunk's is
            // the worst of them: it borrows the target's name *and namespace*, so a tail
            // call into another class would read as that class's member and cut the run in
            // half. Testing the source before the namespace is what keeps that out.
            if (sym.getSource() == SourceType.DEFAULT) continue;
            String name = sym.getName();
            if (name.startsWith("FUN_") || name.startsWith("thunk_")) continue;
            // A linker veneer belongs to no class. It is not a compiler-generated
            // adjustor thunk -- those are ordinary functions in ordinary sections -- and
            // letting one join a class's run would put a stranger in the middle of it.
            if (name.startsWith("$Ven$")) return true;
            Namespace owner = sym.getParentNamespace();
            if (owner instanceof GhidraClass) {
                if (owner.getID() != ns.getID()) return true;
                continue;
            }
            if (!owner.isGlobal()) continue;
            // A mangled label this pipeline wrote is ours; an imported one is not.
            if (name.startsWith("_Z") && sym.getSource() == SourceType.ANALYSIS) continue;
            return true;
        }
        return false;
    }

    /**
     * Cut a forwarding stub loose from its target, the same call processSubVtable makes at
     * RenameVTableFunctions:1941. Ghidra hands a thunk its target's name <em>and</em>
     * namespace, so a stub left attached exports as a second copy of that target's symbol --
     * one mangled name at two addresses. Detaching drops it back to FUN_*.
     */
    private void unthunk(Function func) {
        if (!func.isThunk()) return;
        try {
            func.setThunkedFunction(null);
            stubsDetached++;
        } catch (Exception e) {
            script.println("WARNING: Could not detach stub at " + func.getEntryPoint());
        }
    }

    /**
     * A tail-call stub rather than a member function. The size test is what carries this:
     * these veneers are routinely detached from their target by an earlier pipeline run, so
     * isThunk() has already stopped being true of them by the time this pass sees them.
     */
    private boolean isTrivialStub(Function func) {
        return func.isThunk() || func.getBody().getNumAddresses() <= STUB_MAX_BYTES;
    }

    /** How many bytes between two functions no function in between covers. */
    private long uncovered(List<Function> all, int prev, int here) {
        AddressSet set = gapBytes(all, prev, here);
        return (set == null) ? 0 : set.getNumAddresses();
    }

    /** The stretch between two functions that no function in between covers. */
    private AddressSet gapBytes(List<Function> all, int prev, int here) {
        try {
            Address from = all.get(prev).getBody().getMaxAddress();
            Address to = all.get(here).getEntryPoint();
            if (from == null || to == null) return null;
            if (!from.getAddressSpace().equals(to.getAddressSpace())) return null;
            if (from.compareTo(to) >= 0) return null;

            AddressSet set = new AddressSet(from.add(1), to.subtract(1));
            for (int k = prev + 1; k < here; k++) {
                set.delete(all.get(k).getBody());
            }
            return set;
        } catch (Exception e) {
            return null;
        }
    }

    // ---------------------------------------------------------------
    //  Materialising the code left in a gap
    // ---------------------------------------------------------------

    /**
     * Thumb or ARM, from the members this class already has. A gap inside the run holds more
     * of the same class's code, so it is written in the same instruction set, and guessing
     * wrong makes CreateFunctionCmd follow nonsense.
     */
    private Boolean classThumb(List<Function> all, List<Integer> positions) {
        Register tmode = program.getLanguage().getRegister("TMode");
        if (tmode == null) return null;
        int thumb = 0;
        int arm = 0;
        for (int pos : positions) {
            RegisterValue value = program.getProgramContext()
                    .getRegisterValue(tmode, all.get(pos).getEntryPoint());
            if (value == null || !value.hasValue()) continue;
            if (value.getUnsignedValue().intValue() != 0) thumb++; else arm++;
        }
        if (thumb == 0 && arm == 0) return null;
        return thumb >= arm;
    }

    /**
     * Disassemble the code Ghidra never reached inside a function's own span.
     *
     * Where flow was cut short -- a bl carrying a CALL_RETURN override, most often -- the
     * bytes past it stay undefined even though they sit between the function's first and
     * last instruction. Nothing else picks them up: deriveFunctionBody in FixFunctionBodies
     * walks flow too, so it stops in the same place.
     *
     * The cost is not only the missing code. Those instructions are what load the function's
     * literal pool, so while they stay undefined the pool carries no references, and an
     * unreferenced pool sitting behind a function is indistinguishable from undiscovered
     * code. That is how "STR_Constellation" and the pointer beside it became a member.
     */
    private int fillCodeHoles(Scan scan) {
        int filled = 0;
        for (Map.Entry<Namespace, List<Run>> entry : scan.runs.entrySet()) {
            Boolean thumb = scan.thumb.get(entry.getKey());
            if (thumb == null) continue;
            for (Run run : entry.getValue()) {
                for (Entry member : run.entries) filled += fillHoles(member.func, thumb);
            }
        }
        return filled;
    }

    /** The undisassembled stretches between a function's own first and last instruction. */
    private int fillHoles(Function func, boolean thumb) {
        AddressSetView body = func.getBody();
        Address min = body.getMinAddress();
        Address max = body.getMaxAddress();
        if (min == null || max == null) return 0;

        AddressSet holes = new AddressSet(min, max);
        holes.delete(body);
        if (holes.isEmpty()) return 0;

        Listing listing = program.getListing();
        int filled = 0;
        for (AddressRange hole : holes) {
            Address at = hole.getMinAddress();
            if (listing.getInstructionAt(at) != null) continue;
            // A hole is usually unreached code, but it can be an inline pool between two
            // basic blocks, so it gets the same test a gap head does.
            if (!startsLikeCode(at, thumb)) continue;

            new ArmDisassembleCommand(at, holes, thumb).applyTo(program);
            if (listing.getInstructionAt(at) != null) {
                filled++;
                holesFilled++;
            }
        }
        return filled;
    }

    private int materialise(Scan scan) {
        int created = 0;
        for (Map.Entry<Namespace, List<int[]>> entry : scan.gaps.entrySet()) {
            Boolean thumb = scan.thumb.get(entry.getKey());
            if (thumb == null) continue;
            for (int[] gap : entry.getValue()) {
                AddressSet bytes = gapBytes(scan.all, gap[0], gap[1]);
                if (bytes == null || bytes.isEmpty()) continue;
                AddressSet safe = decodable(bytes);
                if (safe.isEmpty()) continue;

                // Only the stretch immediately after the previous function, and only one
                // function out of it. Flow stops the disassembler at that function's
                // return, and what follows a return is its own data -- the literal pool
                // and the inline strings. Carving on through that is how "P_black" and a
                // pair of pointers became addeqs pc,r4,... and then a class member.
                AddressRange head = safe.getFirstRange();
                if (!head.getMinAddress().equals(bytes.getMinAddress())) continue;
                created += materialiseGapHead(head, safe, thumb);
            }
        }
        return created;
    }

    /**
     * The gap bytes it is safe to decode: the uncovered stretch, less every word that some
     * instruction loads as data.
     *
     * An ARM literal pool sits between functions and belongs to neither body, so it arrives
     * here looking exactly like undiscovered code -- and 0.0f decodes as a perfectly valid
     * "andeq r0,r0,r0". The one thing that tells a constant apart from an instruction is
     * that something reads it, so that is what this asks.
     */
    private AddressSet decodable(AddressSet gap) {
        ReferenceManager refMgr = program.getReferenceManager();
        AddressSet safe = new AddressSet(gap);
        AddressIterator targets = refMgr.getReferenceDestinationIterator(gap, true);
        while (targets.hasNext()) {
            Address target = targets.next();
            for (Reference ref : refMgr.getReferencesTo(target)) {
                if (!ref.getReferenceType().isData()) continue;
                try {
                    safe.delete(target, target.add(WORD_BYTES - 1));
                } catch (Exception e) {
                    safe.delete(target, target);
                }
                literalWordsSkipped++;
                break;
            }
        }
        return safe;
    }

    /**
     * Carve one uncovered stretch into functions. Disassembly comes first and in the class's
     * own mode: CreateFunctionCmd derives a body by following flow, so on undisassembled
     * bytes it produces a one-byte body that later disassembly never grows, and on bytes
     * decoded in the wrong instruction set it follows nonsense.
     *
     * @param safe every gap byte this pass is allowed to decode, which bounds the
     *             disassembler. Unrestricted it follows flow wherever the bytes lead --
     *             out of the gap entirely, or off the end of a function straight into the
     *             literal pool behind it.
     */
    private int materialiseGapHead(AddressRange head, AddressSetView safe, boolean thumb) {
        Listing listing = program.getListing();
        int align = thumb ? 2 : 4;
        Address max = head.getMaxAddress();

        try {
            // Alignment slack after the previous function is zero-filled, and the next
            // real instruction is on the boundary past it.
            Address at = skipPadding(head.getMinAddress(), max);
            if (at == null) return 0;
            long slack = at.getOffset() % align;
            if (slack != 0) at = at.add(align - slack);
            if (at.compareTo(max) > 0) return 0;
            if (max.subtract(at) + 1 < MIN_GAP_FUNCTION_BYTES) return 0;
            if (!startsLikeCode(at, thumb)) { dataHeadsRefused++; return 0; }

            if (listing.getInstructionAt(at) == null) {
                new ArmDisassembleCommand(at, safe, thumb).applyTo(program);
            }
            // Still not code: data sitting in the gap, and nothing to do here.
            if (listing.getInstructionAt(at) == null) return 0;
            if (listing.getFunctionAt(at) != null) return 0;

            new CreateFunctionCmd(at).applyTo(program);
            if (listing.getFunctionAt(at) == null) return 0;
            materialised++;
            return 1;
        } catch (Exception e) {
            return 0;       // ran off the end of the address space
        }
    }

    /**
     * Whether the word here can plausibly begin a function.
     *
     * decodable() only sees a pool that something already loads, and that is not always
     * enough: where Ghidra stopped following flow early -- a bl carrying a CALL_RETURN
     * override, say -- the code past it is never disassembled, so its literal loads were
     * never recorded and the pool they read arrives here unreferenced, looking exactly like
     * undiscovered code. These two tests are what is left to tell them apart.
     *
     * Both lean towards refusing. A function this declines to materialise merely stays in
     * the uncovered-bytes count; one it invents becomes a class member with a rank.
     */
    private boolean startsLikeCode(Address at, boolean thumb) {
        int word;
        try {
            word = program.getMemory().getInt(at);
        } catch (Exception e) {
            return false;
        }
        // A word holding an address into this image is a pointer, not an instruction.
        try {
            if (program.getMemory().contains(
                    at.getNewAddress(Integer.toUnsignedLong(word)))) return false;
        } catch (Exception e) {
            // not a representable address, so not a pointer -- carry on
        }
        // ARM: a function's first instruction is unconditional in practice, so the top
        // nibble is the AL condition. Every mis-decode this has produced carried some
        // other condition there -- 0.0f and three pointers read as EQ, -1.0f as LT --
        // while the real prologues (e92d4070, e92d40f0, e1c500dc) are all AL.
        return thumb || (word >>> 28) == 0xE;
    }

    /** Step over the zero bytes the linker pads with. Null once the range is used up. */
    private Address skipPadding(Address at, Address max) {
        try {
            while (at.compareTo(max) <= 0 && program.getMemory().getByte(at) == 0) {
                at = at.add(1);
            }
        } catch (Exception e) {
            return null;
        }
        return (at.compareTo(max) <= 0) ? at : null;
    }

    // ---------------------------------------------------------------
    //  Model self-checks
    // ---------------------------------------------------------------

    /**
     * D0/D1 are real ABI names and mangle unpadded, as _ZN1XD0Ev. 'D' beats every digit, so
     * they sort after everything this pass emits and belong at the end of the run, D0 then
     * D1. Where they do not, the sort model does not hold for that class and nothing
     * claimed there should be trusted.
     */
    private void checkDestructorTail(Namespace ns, Run run) {
        List<Entry> entries = run.entries;
        int firstDtor = -1;
        for (int i = 0; i < entries.size(); i++) {
            if (entries.get(i).dtorKind != null) { firstDtor = i; break; }
        }
        if (firstDtor < 0) return;

        boolean tail = true;
        for (int i = firstDtor; i < entries.size(); i++) {
            if (entries.get(i).dtorKind == null) { tail = false; break; }
        }
        boolean ordered = "D0".equals(entries.get(firstDtor).dtorKind);

        if (tail && ordered) {
            dtorTailOk++;
        } else if (dtorTailFailures.size() < 20) {
            dtorTailFailures.add(String.format("    %s: destructors at index %d of %d%s",
                    ns.getName(true), firstDtor, entries.size(),
                    ordered ? "" : ", and D1 precedes D0"));
        }
    }

    /**
     * Constructors mangle C1/C2, and 'C' also beats every digit, so anything sitting between
     * the last vtable slot and D0 is a constructor before it is anything else. Report those
     * rather than handing them a made-up non-virtual name.
     */
    private void setAsideConstructorCandidates(Namespace ns, Run run) {
        List<Entry> entries = run.entries;
        int firstDtor = -1;
        for (int i = 0; i < entries.size(); i++) {
            if (entries.get(i).dtorKind != null) { firstDtor = i; break; }
        }
        if (firstDtor < 0) return;

        int lastNamed = -1;
        for (int i = 0; i < firstDtor; i++) {
            if (!entries.get(i).claimed) lastNamed = i;
        }

        for (int i = firstDtor - 1; i > lastNamed; i--) {
            Entry entry = entries.get(i);
            if (!entry.claimed) continue;
            ctorCandidates++;
            if (ctorCandidateLines.size() < 40) {
                ctorCandidateLines.add(String.format("    %s at %s",
                        ns.getName(true), entry.addr));
            }
            entries.remove(i);
        }
    }

    // ---------------------------------------------------------------
    //  Assignment
    // ---------------------------------------------------------------

    /**
     * Name every entry of one run, in address order. Handing out ranks in that order is the
     * whole of it: the rank leads a fixed-width name, so it decides the sort outright and
     * the result cannot come out misordered. There is nothing to search and nothing to fail
     * at, which is why the padded scheme's ladder, tiers and retry loop are gone.
     *
     * @param counters this class's next rank and next non-virtual letters, carried
     *                 across all of its runs
     */
    private void assign(Namespace ns, Run run, Counters counters) {
        for (Entry entry : run.entries) {
            entry.name = null;

            // A real name and the destructor pair are fixed points: D0/D1 are the true ABI
            // spelling, and an imported name sorts by its own mangling, which this pass
            // cannot compute. Neither takes a rank.
            if (entry.fixed) continue;

            if (counters.rank > MAX_FIELD || entry.slot > MAX_FIELD
                    || counters.nonVirtual > MAX_SEQUENCE) {
                if (overflows.size() < 20) {
                    overflows.add(String.format("    %s at %s: rank %d, slot %d, sequence %d",
                            ns.getName(true), entry.addr, counters.rank, entry.slot,
                            counters.nonVirtual));
                }
                continue;
            }
            entry.name = memberName(counters.rank++, entry.virtual(), entry.slot,
                    entry.virtual() ? 0 : counters.nonVirtual++);
        }
    }

    // ---------------------------------------------------------------
    //  Application
    // ---------------------------------------------------------------

    private void apply(Namespace ns, Run run) {
        // Re-ranking shuffles names within a class, so a target can be sitting on a
        // function that is itself about to move -- M095 wants a name M094 still holds.
        // Parking everything that changes on an address-unique temporary first makes the
        // second pass collision-free whatever the permutation.
        for (Entry entry : run.entries) {
            if (entry.name == null) continue;
            try {
                if (entry.claimed && entry.func.isThunk()) {
                    // Ghidra names a thunk after whatever it forwards to, which puts that
                    // symbol at a second address and wrecks the export. Detaching it is
                    // what lets the name below stick.
                    entry.func.setThunkedFunction(null);
                    thunksClaimed++;
                }
                Symbol sym = placeholderSymbol(entry.func);
                if (sym == null || sym.getName().equals(entry.name)) continue;

                if (entry.claimed) {
                    sym.setNamespace(ns);
                    setThisCall(entry.func);
                    gapsClaimed++;
                } else {
                    slotsRenamed++;
                }
                sym.setName("M_" + entry.addr, SourceType.USER_DEFINED);
            } catch (Exception e) {
                script.println("ERROR: Could not park " + ns.getName(true) + "::" +
                        entry.name + " at " + entry.addr + ": " + e.getMessage());
            }
        }

        for (Entry entry : run.entries) {
            if (entry.name == null) continue;
            try {
                Symbol sym = placeholderSymbol(entry.func);
                if (sym == null) continue;
                if (!sym.getName().equals(entry.name)) {
                    sym.setName(entry.name, SourceType.USER_DEFINED);
                }
            } catch (Exception e) {
                script.println("ERROR: Could not name " + ns.getName(true) + "::" +
                        entry.name + " at " + entry.addr + ": " + e.getMessage());
                continue;
            }
            emitMangled(ns, entry);
            updateVtableFields(entry);
        }
    }

    /**
     * Rename this function's slot in every vtable struct that holds it.
     *
     * buildVtableStructs in RenameVTableFunctions names each field after whatever the slot
     * target was called at the time, so after a rename the struct still reads VF02 and the
     * decompiler shows a name nothing carries. The vtable slots are the data references to
     * the function, so following those back lands on the struct component to fix -- which
     * covers secondary sub-vtables and inherited slots shared with a base without this pass
     * needing to know any of the vtable layout.
     */
    private void updateVtableFields(Entry entry) {
        Listing listing = program.getListing();
        for (Reference ref : program.getReferenceManager().getReferencesTo(entry.addr)) {
            Address from = ref.getFromAddress();
            if (listing.getInstructionAt(from) != null) continue;   // a call, not a slot

            Data slot = listing.getDataContaining(from);
            if (slot == null) continue;
            Data parent = slot.getParent();
            if (parent == null) continue;
            if (!(parent.getDataType() instanceof Structure struct)) continue;

            int index = slot.getComponentIndex();
            if (index < 0 || index >= struct.getNumComponents()) continue;
            try {
                DataTypeComponent field = struct.getComponent(index);
                if (entry.name.equals(field.getFieldName())) continue;
                field.setFieldName(entry.name);
                vtableFieldsUpdated++;
            } catch (Exception e) {
                script.println("WARNING: Could not rename " + struct.getName() +
                        " field " + index + " to " + entry.name);
            }
        }
    }

    private void setThisCall(Function func) {
        try {
            if (!"__thiscall".equals(func.getCallingConventionName())) {
                func.updateFunction("__thiscall", null, List.of(),
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                        true, SourceType.USER_DEFINED);
            }
        } catch (Exception e) { /* may already be set */ }
    }

    /**
     * Re-spell the mangled label. Renaming invalidates the one RenameVTableFunctions wrote
     * -- _ZN1X4VF02Ev becomes _ZN1X8M007V002Ev -- so the stale label has to go first, or the
     * address ends up carrying two mangled names that contradict each other. Only labels
     * this pipeline wrote are touched; an imported or user-toggled mangled name is real and
     * stops the write.
     */
    private void emitMangled(Namespace ns, Entry entry) {
        // Structors only. Anything else this pass names is its own placeholder (M007V002)
        // or a member whose parameters and const-ness nothing here knows, and a mangled
        // spelling would assert both. The stale mangled label is still cleared below.
        boolean structor = switch (entry.name) {
            case "C1", "C2", "C3", "D0", "D1", "D2" -> true;
            default -> false;
        };
        String mangled = structor ? RenameVTableFunctions.mangle(ns, entry.name) : null;
        if (mangled == null) {
            clearStaleMangled(entry);
            return;
        }

        // One name, one address. armcc/armlink 4.1 fold no identical code, so a mangled
        // name has exactly one address; the only sharing is several names on one address.
        // Without this, a member claimed into a class's run could be given a name that a
        // vtable slot had already put somewhere else -- _ZN17AudioObjFurnitureD1Ev ended
        // up on both 0x2c4fe8 (the real destructor) and 0x324a10 (the base's, which it
        // tail-calls). Neither this pass nor the export can tell which is right, so the
        // second one is not written and is reported instead.
        for (Symbol other : symTab.getGlobalSymbols(mangled)) {
            if (!other.getAddress().equals(entry.addr)) {
                script.printf("    WARNING: %s already at %s; not writing it at %s too\n",
                        mangled, other.getAddress(), entry.addr);
                return;
            }
        }

        Symbol funcSym = entry.func.getSymbol();
        for (Symbol sym : symTab.getSymbols(entry.addr)) {
            if (!sym.getName().startsWith("_Z")) continue;
            if (sym.getSource() != SourceType.ANALYSIS || sym.equals(funcSym)) return;
            if (sym.getName().equals(mangled)) return;
            sym.delete();
        }
        try {
            symTab.createLabel(entry.addr, mangled, program.getGlobalNamespace(),
                    SourceType.ANALYSIS);
            mangledEmitted++;
        } catch (Exception e) {
            script.println("WARNING: Could not label " + mangled + " at " + entry.addr);
        }
    }

    /** Drop a mangled label an earlier run of this pass wrote for a non-structor name. */
    private void clearStaleMangled(Entry entry) {
        Symbol funcSym = entry.func.getSymbol();
        for (Symbol sym : symTab.getSymbols(entry.addr)) {
            if (!sym.getName().startsWith("_Z")) continue;
            if (sym.getSource() != SourceType.ANALYSIS || sym.equals(funcSym)) continue;
            // Only ones spelled from this pass's own naming scheme.
            // VIRTUAL_FORMAT / NONVIRTUAL_FORMAT, as mangle() spells them.
            if (sym.getName().matches("_ZN.*\\d+M\\d{3}[VN]\\w*Ev")) sym.delete();
        }
    }

    // ---------------------------------------------------------------
    //  Report
    // ---------------------------------------------------------------

    private void report() {
        script.printf("    Classes / runs:         %d classes in %d runs, %d cut short by " +
                "a foreign symbol, %d tail-call stubs stepped over without cutting one " +
                "(%d of them detached from their target)\n",
                classesSeen, runsSeen, runBreaks, stubsStepped, stubsDetached);
        script.printf("    Non-virtuals claimed:   %d named, of them %d branch thunks " +
                "detached from their target and %d disassembled out of gap bytes " +
                "(%d words left alone as literal pool, %d gaps refused as data)\n",
                gapsClaimed, thunksClaimed, materialised, literalWordsSkipped,
                dataHeadsRefused);
        script.printf("    Code recovered:         %d holes disassembled inside function " +
                "bodies that flow never reached\n", holesFilled);
        script.printf("    Dropped:                %d candidates in a gap that was cut " +
                "short, %d bytes still covered by no function, %d fragments of the " +
                "function before them left as FUN_\n",
                candidatesDropped, uncoveredBytes, fragmentsSkipped);
        script.printf("    Slots renamed:          %d, %d mangled labels written, " +
                "%d vtable struct fields retitled, %d members left alone with real names\n",
                slotsRenamed, mangledEmitted, vtableFieldsUpdated, fixedMembers);

        script.printf("    Destructor tail check:  %d runs end in D0, D1 as the model " +
                "predicts; %d do not\n", dtorTailOk, dtorTailFailures.size());
        for (String line : dtorTailFailures) script.println(line);
        if (!dtorTailFailures.isEmpty()) {
            script.println("    (a high failure rate means the sort model does not hold " +
                    "here and nothing claimed above is trustworthy)");
        }

        if (ctorCandidates > 0) {
            script.printf("    Constructor candidates: %d left unnamed between the last slot " +
                    "and D0\n", ctorCandidates);
            for (String line : ctorCandidateLines) script.println(line);
        }
        if (!overflows.isEmpty()) {
            script.printf("    Left unnamed:           %d past the three-digit rank or " +
                    "slot fields\n", overflows.size());
            for (String line : overflows) script.println(line);
        }
    }
}
