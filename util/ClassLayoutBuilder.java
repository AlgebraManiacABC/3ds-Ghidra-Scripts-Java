package util;

import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Give each class struct the members it inherits, then let the decompiler discover the
 * ones it declares itself.
 *
 * <p>Nothing else in the pipeline sizes a class struct. A class comes out of
 * {@link RenameVTableFunctions} as {@code { vtbl; }} -- or empty, if it has no vtable at
 * all -- so when the decompiler works out that a derived object holds its base subobject
 * at offset 0 and tries to say so, the write is dropped for want of room: Ghidra's
 * {@code replaceAtOffset} consumes undefined bytes that are already there and never grows
 * the structure. The base's members are then rediscovered, unnamed, in every child that
 * happens to touch them.
 *
 * <p>So walk the class graph parents first, and for each class in turn copy the finished
 * bases' members in before filling. A class is only reached once <em>every</em> one of its
 * parents is done, which is what makes multiple inheritance and diamonds come out in a
 * usable order.
 *
 * <p>Members are copied rather than the base struct being embedded whole. Embedding would
 * be byte-accurate but would type offset 0 as the <em>base's</em> vtable pointer, when the
 * object's vptr points at the derived class's vtable. Copying keeps each class's own vptr,
 * and the defined fields it leaves behind also fend off the decompiler's later attempts to
 * drop a base subobject on top of them.
 *
 * <p>No vtable pointer is ever inherited, for the same reason: every vptr in a class --
 * the primary one and the secondary one each non-primary polymorphic base contributes --
 * is derived from that class's own sub-vtables.
 */
public class ClassLayoutBuilder {

    private static final int PTR_SIZE = 4;

    /** Ghidra's own spelling for a component nobody named; not worth carrying over. */
    private static final Pattern DEFAULT_FIELD_NAME = Pattern.compile("field_0x[0-9a-fA-F]+");

    /** How hard {@link #place} tries when the offset is already occupied. */
    private enum Mode {
        /** An inherited member: leave whatever is already defined there alone. */
        MEMBER,
        /** A vtable pointer: the class's own vptr is right, so it displaces a member. */
        VPTR
    }

    /**
     * One module's share of the class graph, copied out of {@link RenameVTableFunctions}
     * before its next {@code run()} clears it.
     */
    public record ModuleInfo(Program program,
                             Map<String, List<BaseRef>> baseInfo,
                             Map<String, List<Structure>> classVfuncs,
                             Map<String, List<Address>> vtableHeads,
                             Map<String, List<VtableScan.SubTable>> subTables,
                             Map<String, Namespace> classNamespaces) {

        public static ModuleInfo snapshot(Program program, RenameVTableFunctions renamer) {
            return new ModuleInfo(program,
                    new HashMap<>(renamer.getBaseInfo()),
                    new HashMap<>(renamer.getClassVfuncs()),
                    new HashMap<>(renamer.getVtableHeads()),
                    new HashMap<>(renamer.getVtableSubTables()),
                    new HashMap<>(renamer.getClassNamespaces()));
        }
    }

    private final GhidraScript script;
    private final GhidraState state;
    private final TaskMonitor monitor;
    private final List<ModuleInfo> modules;

    // class name -> its bases, merged across every module that described it
    private final Map<String, List<BaseRef>> bases = new LinkedHashMap<>();
    // class name -> the classes naming it as a base
    private final Map<String, List<String>> children = new HashMap<>();
    // every class with a vtable in any module, so a class defined in code.bin still reads
    // as polymorphic while its stub is being laid out inside a .cro
    private final Set<String> polymorphic = new HashSet<>();
    // the fullest struct found for a base, safe to cache because the traversal finishes a
    // class in every module before any class deriving from it is reached
    private final Map<String, Structure> baseStructCache = new HashMap<>();
    // one message per distinct problem: a class shared by nine modules is laid out nine
    // times and would otherwise say the same thing nine times
    private final Set<String> reported = new HashSet<>();

    private int classesLaidOut = 0;
    private int membersCopied = 0;
    private int bytesGrown = 0;
    private int vptrsPlaced = 0;
    private int vptrsUnresolved = 0;
    private int plainBases = 0;
    private int virtualBasesSkipped = 0;
    private int virtualBasesResolved = 0;
    private int virtualBasesByOffsetFlags = 0;
    private int conflicts = 0;
    private AutoFillClasses.Counts fillTotals = AutoFillClasses.Counts.ZERO;

    public ClassLayoutBuilder(GhidraScript script, GhidraState state, TaskMonitor monitor,
                              List<ModuleInfo> modules) {
        this.script = script;
        this.state = state;
        this.monitor = monitor;
        this.modules = modules;
    }

    /**
     * Lay out every class in every module, parents before children. Each module's writes
     * are wrapped in one transaction here rather than by the caller, because the traversal
     * is global: a base in code.bin has to be finished before the .cro classes deriving
     * from it, so the modules are not visited one after another.
     */
    public String run() {
        buildGraph();
        List<String> order = topologicalOrder();

        Map<Program, Integer> transactions = new LinkedHashMap<>();
        boolean commit = false;
        try {
            for (ModuleInfo m : modules) {
                transactions.put(m.program(),
                        m.program().startTransaction("Build Class Layouts"));
            }

            monitor.setMaximum(order.size());
            for (int i = 0; i < order.size(); i++) {
                if (monitor.isCancelled()) break;
                String className = order.get(i);
                monitor.setProgress(i);
                monitor.setMessage(String.format("[%d/%d] %s", i + 1, order.size(), className));
                layOutEverywhere(className);
            }
            commit = true;
        } finally {
            for (Map.Entry<Program, Integer> e : transactions.entrySet()) {
                e.getKey().endTransaction(e.getValue(), commit);
            }
        }

        return "\n=== CLASS LAYOUT SUMMARY ===" +
                "\n\tClasses laid out:    " + classesLaidOut +
                "\n\tMembers inherited:   " + membersCopied +
                "\n\tBytes grown:         " + bytesGrown +
                "\n\tSecondary vptrs:     " + vptrsPlaced + " placed, " +
                vptrsUnresolved + " unresolved" +
                "\n\tNon-virtual bases:   " + plainBases +
                "\n\tVirtual bases:       " + virtualBasesResolved +
                " resolved from vbase offsets (" + virtualBasesByOffsetFlags +
                " located by __offset_flags), " + virtualBasesSkipped + " left undefined" +
                "\n\tOffset conflicts:    " + conflicts +
                "\n\tAuto-fill:           " + fillTotals;
    }

    // ---------------------------------------------------------------
    //  Graph
    // ---------------------------------------------------------------

    private void buildGraph() {
        for (ModuleInfo m : modules) {
            for (Map.Entry<String, List<BaseRef>> e : m.baseInfo().entrySet()) {
                List<BaseRef> merged = bases.computeIfAbsent(e.getKey(),
                        k -> new ArrayList<>());
                for (BaseRef b : e.getValue()) {
                    // The same edge is described by every module that resolved it.
                    if (!merged.contains(b)) merged.add(b);
                }
            }
            polymorphic.addAll(m.classVfuncs().keySet());
        }
        for (Map.Entry<String, List<BaseRef>> e : bases.entrySet()) {
            for (BaseRef b : e.getValue()) {
                children.computeIfAbsent(b.name(), k -> new ArrayList<>()).add(e.getKey());
            }
        }
    }

    /** Every class name any module knows about, whether or not it has bases. */
    private Set<String> allClassNames() {
        Set<String> names = new LinkedHashSet<>();
        for (ModuleInfo m : modules) names.addAll(m.classNamespaces().keySet());
        names.addAll(bases.keySet());
        for (List<BaseRef> refs : bases.values()) {
            for (BaseRef b : refs) names.add(b.name());
        }
        return names;
    }

    /**
     * Parents before children, by Kahn's algorithm: a class is released only once every
     * base it names has already been emitted. Anything still held back at the end sits on
     * a cycle -- which the ABI does not allow, so it means the RTTI was misread -- and is
     * emitted anyway rather than dropped.
     */
    private List<String> topologicalOrder() {
        Set<String> names = allClassNames();
        Map<String, Integer> pending = new LinkedHashMap<>();
        for (String n : names) {
            int count = 0;
            for (BaseRef b : bases.getOrDefault(n, List.of())) {
                if (names.contains(b.name()) && !b.name().equals(n)) count++;
            }
            pending.put(n, count);
        }

        Deque<String> ready = new ArrayDeque<>();
        for (Map.Entry<String, Integer> e : pending.entrySet()) {
            if (e.getValue() == 0) ready.add(e.getKey());
        }

        List<String> order = new ArrayList<>(names.size());
        Set<String> emitted = new HashSet<>();
        while (!ready.isEmpty()) {
            String n = ready.poll();
            order.add(n);
            emitted.add(n);
            for (String child : children.getOrDefault(n, List.of())) {
                Integer left = pending.get(child);
                if (left == null || left == 0) continue;
                left--;
                pending.put(child, left);
                if (left == 0) ready.add(child);
            }
        }

        if (order.size() < names.size()) {
            List<String> stuck = new ArrayList<>();
            for (String n : names) if (!emitted.contains(n)) stuck.add(n);
            script.println("    WARNING: " + stuck.size() + " classes sit on an " +
                    "inheritance cycle and are laid out in an arbitrary order: " +
                    stuck.subList(0, Math.min(8, stuck.size())) +
                    (stuck.size() > 8 ? " ..." : ""));
            order.addAll(stuck);
        }
        return order;
    }

    // ---------------------------------------------------------------
    //  Layout
    // ---------------------------------------------------------------

    private void layOutEverywhere(String className) {
        List<BaseRef> myBases = bases.getOrDefault(className, List.of());

        for (ModuleInfo m : modules) {
            Namespace ns = m.classNamespaces().get(className);
            if (ns == null) continue;
            GhidraClass cls = asClass(m.program(), ns);
            if (cls == null) continue;

            Structure cs = classStruct(m.program(), cls);
            if (cs == null) continue;

            if (cs.isPackingEnabled()) {
                if (once("packed", className, "")) {
                    script.println("    WARNING: " + className + " has packing enabled; " +
                            "leaving its layout alone");
                }
                continue;
            }

            // Members first, every base, then the vtable pointers. A vptr has to be able
            // to displace an inherited member sitting at its offset -- the class's own
            // vptr is the right value there -- and doing them in one pass would let base
            // order decide which won.
            for (BaseRef base : myBases) {
                copyMembers(m, className, cs, base);
            }
            for (BaseRef base : myBases) {
                if (!isPolymorphic(base.name())) continue;
                // A virtual base's position comes from the vbase-offset words, so it can
                // now carry a secondary vptr like any other base at a non-zero offset.
                Integer at = base.isVirtual() ? virtualBaseOffset(className, base)
                                              : base.offset();
                if (at == null || at <= 0) continue;
                placeSecondaryVptr(m, className, cs, base, at);
            }

            DecompileOptions options = AutoFillClasses.optionsFor(state, m.program());
            fillTotals = fillTotals.plus(
                    AutoFillClasses.fillClass(cls, options, m.program(), monitor));
            classesLaidOut++;
        }
    }

    private void copyMembers(ModuleInfo m, String childName, Structure child, BaseRef base) {
        int at;
        if (base.isVirtual()) {
            // __offset_flags does not carry a virtual base's position; the vbase-offset
            // words at the head of the primary sub-table do. Resolve it from there.
            Integer resolved = virtualBaseOffset(childName, base);
            if (resolved == null) {
                if (once("virtual", childName, base.name())) {
                    virtualBasesSkipped++;
                    script.println("    NOTE: " + childName + " inherits virtually from " +
                            base.name() + " but its offset could not be resolved; its " +
                            "members are left undefined");
                }
                return;
            }
            at = resolved;
            virtualBasesResolved++;
        } else {
            at = base.offset();
        }
        if (at < 0) {
            if (once("negative", childName, base.name())) {
                script.println("    WARNING: " + childName + " names " + base.name() +
                        " at negative offset " + at + "; skipping");
            }
            return;
        }
        plainBases++;

        Structure baseStruct = bestBaseStruct(base.name());
        if (baseStruct == null) return;

        DataTypeManager dtm = m.program().getDataTypeManager();
        Set<String> takenNames = new HashSet<>();
        for (DataTypeComponent dc : child.getDefinedComponents()) {
            String n = realName(dc.getFieldName());
            if (n != null) takenNames.add(n);
        }

        for (DataTypeComponent dc : baseStruct.getDefinedComponents()) {
            DataType dt = dc.getDataType();

            // Never inherit a vptr. A base's vtable pointer -- its own at offset 0, or a
            // secondary one it inherited in turn -- names the base's vtable, and this
            // object's vptrs point at this class's. They are rebuilt in the second pass.
            if (isVtablePointer(dt)) continue;
            if (Undefined.isUndefined(dt)) continue;   // nothing the child does not know
            if (dc.isBitFieldComponent()) {
                if (once("bitfield", childName, base.name())) {
                    script.println("    WARNING: skipping bitfield " + dc.getFieldName() +
                            " of " + base.name() + " when copying into " + childName);
                }
                continue;
            }

            int target = at + dc.getOffset();
            int len = dc.getLength();
            if (!ensureRoom(child, target + len, childName)) continue;

            DataType local = dtm.resolve(dt, DataTypeConflictHandler.KEEP_HANDLER);
            String name = realName(dc.getFieldName());
            if (name != null && takenNames.contains(name)
                    && !name.equals(realName(nameAt(child, target)))) {
                name = name + "_" + flat(base.name());
            }

            if (place(child, target, local, len, name, dc.getComment(), childName, Mode.MEMBER)) {
                if (name != null) takenNames.add(name);
                membersCopied++;
            }
        }
    }

    /**
     * Where a virtual base subobject actually sits in {@code childName}.
     *
     * <p>{@link BaseRef#offset()} names the <em>vbase-offset word</em> that holds the
     * position, as a byte offset from the address point -- not the position itself. That
     * convention is now established, so the first route is to decode it directly with
     * {@link BaseRef#vbaseOffsetIndex(int)} and read the word it names.
     *
     * <p>The older value-match survives as a fallback for the cases the decode cannot
     * serve: a class whose vbase-offset run was not recovered at the width the typeinfo
     * assumes (a virtual base declared in an unresolved module, say), where the index
     * lands outside the run. There it takes the vbase-offset words at the head of the
     * class's primary sub-table and picks the one a secondary sub-table confirms, or the
     * only one left unclaimed. An ambiguous answer is refused rather than guessed -- a
     * wrong offset scatters the base's members through the middle of the derived class.
     */
    private Integer virtualBaseOffset(String childName, BaseRef base) {
        int[] candidates = vbaseOffsetsOf(childName);
        if (candidates.length == 0) return null;

        // Documented route: __offset_flags points straight at the word.
        int index = base.vbaseOffsetIndex(candidates.length);
        if (index >= 0) {
            int at = candidates[index];
            if (at > 0) {
                virtualBasesByOffsetFlags++;
                return at;
            }
        }

        // Offsets a sub-table vouches for: a secondary whose offset-to-top is -N says a
        // subobject really starts at N.
        Set<Integer> confirmed = new HashSet<>();
        for (ModuleInfo m : modules) {
            List<VtableScan.SubTable> subs = m.subTables().get(childName);
            if (subs == null) continue;
            for (VtableScan.SubTable s : subs) {
                if (s.offsetToTop() < 0) confirmed.add(-s.offsetToTop());
            }
        }

        // Every virtual base in declaration order, so an unambiguous single candidate can
        // be attributed and a contested one refused.
        List<BaseRef> virtuals = new ArrayList<>();
        for (BaseRef b : bases.getOrDefault(childName, List.of())) {
            if (b.isVirtual()) virtuals.add(b);
        }
        if (virtuals.size() == 1 && candidates.length == 1) return candidates[0];

        // With several of each, only a confirmed offset at the base's own index is safe.
        int declIndex = virtuals.indexOf(base);
        if (declIndex < 0 || declIndex >= candidates.length) return null;
        int at = candidates[declIndex];
        if (at <= 0 || !confirmed.contains(at)) return null;
        return at;
    }

    /** The vbase-offset words on the primary sub-table of a class, from any module. */
    private int[] vbaseOffsetsOf(String className) {
        for (ModuleInfo m : modules) {
            List<VtableScan.SubTable> subs = m.subTables().get(className);
            if (subs == null || subs.isEmpty()) continue;
            // Only the table at offset-to-top 0 carries the object's vbase-offset run. A
            // sub-table for a base subobject carries vcall offsets, which are a different
            // thing entirely and would place members at nonsense offsets.
            if (subs.get(0).hasVcallOffsets()) continue;
            int[] offsets = subs.get(0).vbaseOffsets();
            if (offsets.length > 0) return offsets;
        }
        return new int[0];
    }

    /**
     * A polymorphic base at a non-zero offset starts a second subobject, so its first word
     * is a second vptr -- one pointing into <em>this</em> class's vtable, at the sub-vtable
     * whose offset-to-top is the negation of where the subobject sits.
     */
    private void placeSecondaryVptr(ModuleInfo m, String childName, Structure child,
                                    BaseRef base, int at) {
        Structure vfuncs = findSubVtable(childName, at);
        if (vfuncs == null) {
            if (once("novtbl", childName, base.name())) {
                vptrsUnresolved++;
                script.println("    WARNING: no sub-vtable of " + childName +
                        " has offset-to-top " + (-at) + " for its " + base.name() +
                        " subobject; leaving that vptr untyped");
            }
            return;
        }
        if (!ensureRoom(child, at + PTR_SIZE, childName)) return;

        DataTypeManager dtm = m.program().getDataTypeManager();
        DataType ptr = new PointerDataType(
                dtm.resolve(vfuncs, DataTypeConflictHandler.KEEP_HANDLER), PTR_SIZE);
        if (place(child, at, ptr, PTR_SIZE, "vtbl_" + flat(base.name()),
                "vtable pointer for the " + base.name() + " subobject",
                childName, Mode.VPTR)) {
            vptrsPlaced++;
        }
    }

    private void placeSecondaryVptr(ModuleInfo m, String childName, Structure child,
                                    BaseRef base) {
        placeSecondaryVptr(m, childName, child, base, base.offset());
    }

    /**
     * The function-slot struct of whichever sub-vtable of {@code className} sits
     * {@code at} bytes down from the top of the object. Searched across every module: a
     * class defined in code.bin keeps its vtable there, even while a .cro's stub of it is
     * the struct being written.
     */
    private Structure findSubVtable(String className, int at) {
        for (ModuleInfo m : modules) {
            List<Structure> vfuncs = m.classVfuncs().get(className);
            List<VtableScan.SubTable> subs = m.subTables().get(className);
            if (vfuncs == null || subs == null || vfuncs.size() != subs.size()) continue;
            for (int v = 0; v < subs.size(); v++) {
                // The recorded value, not a read of the head word. A class with virtual
                // bases has vbase-offset words in front of offset-to-top, so the head is
                // no longer the offset-to-top word and reading it there is wrong.
                if (subs.get(v).offsetToTop() == -at) return vfuncs.get(v);
            }
        }
        return null;
    }

    /**
     * Whether a class has virtual functions, so a base subobject of it carries a vptr.
     * A vtable in any module counts; so does a class struct that already starts with a
     * vptr, which covers classes whose vtable struct could not be built.
     */
    private boolean isPolymorphic(String className) {
        if (polymorphic.contains(className)) return true;
        Structure cs = bestBaseStruct(className);
        if (cs != null) {
            DataTypeComponent first = cs.getComponentContaining(0);
            if (first != null && first.getOffset() == 0 && isVtablePointer(first.getDataType())) {
                polymorphic.add(className);
                return true;
            }
        }
        return false;
    }

    private static boolean isVtablePointer(DataType dt) {
        return dt instanceof Pointer p
                && p.getDataType() instanceof Structure s
                && RenameVTableFunctions.VTABLE_PATH.equals(s.getCategoryPath());
    }

    /**
     * Append undefined bytes until the struct is at least {@code minLength} long.
     *
     * <p>{@code getLength()} reports 1 for a structure of length 0 -- Ghidra requires a
     * positive length -- while {@code growStructure} adds exactly what it is given, so
     * asking for the difference between the two under-grows an empty struct by a byte.
     * Every class without a vtable starts out empty, which is most of them.
     */
    private boolean ensureRoom(Structure s, int minLength, String owner) {
        int current = s.isZeroLength() ? 0 : s.getLength();
        int grow = minLength - current;
        if (grow <= 0) return true;
        try {
            s.growStructure(grow);
            bytesGrown += grow;
        } catch (Exception e) {
            if (once("grow", owner, "")) {
                script.println("    WARNING: could not grow " + owner + " to " +
                        minLength + " bytes: " + e.getMessage());
            }
            return false;
        }
        if (s.getLength() < minLength) {
            if (once("grow", owner, "")) {
                script.println("    WARNING: " + owner + " is " + s.getLength() +
                        " bytes after growing; " + minLength + " were needed");
            }
            return false;
        }
        return true;
    }

    private static String nameAt(Structure s, int offset) {
        DataTypeComponent dc = s.getComponentContaining(offset);
        return (dc == null || dc.getOffset() != offset) ? null : dc.getFieldName();
    }

    /** A name worth carrying into the child, or null for one Ghidra made up. */
    private static String realName(String name) {
        if (name == null || name.isBlank()) return null;
        return DEFAULT_FIELD_NAME.matcher(name).matches() ? null : name;
    }

    private static String flat(String className) {
        return className.replace("::", "_");
    }

    private static String describe(DataType dt, String name) {
        return name == null ? dt.getName() : dt.getName() + " " + name;
    }

    /**
     * Write one component. Re-running the pipeline has to be a no-op, so an identical type
     * already in place is left alone. Beyond that, an inherited member yields to whatever
     * is already defined -- a member the decompiler worked out beats a copied guess --
     * while a vptr displaces it, because the class's own vtable pointer is the one true
     * value at that offset.
     */
    private boolean place(Structure s, int offset, DataType dt, int len, String name,
                          String comment, String owner, Mode mode) {
        DataTypeComponent existing = s.getComponentContaining(offset);
        boolean occupied = existing != null && !Undefined.isUndefined(existing.getDataType());
        if (occupied) {
            if (existing.getOffset() == offset && existing.getLength() == len
                    && existing.getDataType().isEquivalent(dt)) {
                return false;   // already written on an earlier run
            }
            if (mode == Mode.MEMBER) {
                // A vptr already sitting here is this class's own and outranks the copy.
                if (!isVtablePointer(existing.getDataType())
                        && once("clash", owner, offset + "/" + dt.getName())) {
                    conflicts++;
                    script.println("    NOTE: " + owner + " already defines " +
                            describe(existing.getDataType(), existing.getFieldName()) +
                            " at offset 0x" + Integer.toHexString(offset) +
                            "; not overwriting it with " + describe(dt, name));
                }
                return false;
            }
        }
        try {
            s.replaceAtOffset(offset, dt, len, name, comment);
            return true;
        } catch (Exception e) {
            if (once("place", owner, offset + "/" + dt.getName())) {
                conflicts++;
                script.println("    WARNING: could not place " + describe(dt, name) +
                        " at offset 0x" + Integer.toHexString(offset) + " of " + owner +
                        ": " + e.getMessage());
            }
            return false;
        }
    }

    private boolean once(String kind, String owner, String detail) {
        return reported.add(kind + '\0' + owner + '\0' + detail);
    }

    // ---------------------------------------------------------------
    //  Struct lookup
    // ---------------------------------------------------------------

    /**
     * The fullest version of a class's struct anywhere in the project. A class defined in
     * code.bin also gets an empty stub in every .cro that names it as a base, and it is the
     * module the class actually lives in that has its members.
     */
    private Structure bestBaseStruct(String baseName) {
        if (baseStructCache.containsKey(baseName)) return baseStructCache.get(baseName);

        Structure best = null;
        for (ModuleInfo m : modules) {
            Namespace ns = m.classNamespaces().get(baseName);
            if (ns == null) continue;
            GhidraClass cls = asClass(m.program(), ns);
            if (cls == null) continue;
            Structure cs = VariableUtilities.findExistingClassStruct(
                    cls, m.program().getDataTypeManager());
            if (cs == null || cs.isZeroLength()) continue;
            if (best == null || cs.getLength() > best.getLength()) best = cs;
        }
        baseStructCache.put(baseName, best);
        return best;
    }

    private Structure classStruct(Program prog, GhidraClass cls) {
        DataTypeManager dtm = prog.getDataTypeManager();
        Structure cs = VariableUtilities.findExistingClassStruct(cls, dtm);
        if (cs != null) return cs;
        Structure placeholder = VariableUtilities.findOrCreateClassStruct(cls, dtm);
        if (placeholder == null) {
            if (once("nostruct", cls.getName(true), "")) {
                script.println("    WARNING: no class struct available for " + cls.getName(true));
            }
            return null;
        }
        return (Structure) dtm.resolve(placeholder, DataTypeConflictHandler.KEEP_HANDLER);
    }

    private GhidraClass asClass(Program prog, Namespace ns) {
        if (ns instanceof GhidraClass gc) return gc;
        try {
            return prog.getSymbolTable().convertNamespaceToClass(ns);
        } catch (Exception e) {
            return null;
        }
    }
}
