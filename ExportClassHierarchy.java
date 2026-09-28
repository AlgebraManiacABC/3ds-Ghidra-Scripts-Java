// ExportClassHierarchy.java
// Exports every class in the program (plus any external CRO classes reachable
// through RTTI base pointers) together with its namespace and its direct base
// classes, using the __cxxabiv1 typeinfo structures already parsed by
// CROLink / ProcessAllRTTI.
//
// Output is a single text file with four sections:
//
//   [CLASSES]      tab-separated: full_name, namespace, simple_name,
//                  rtti_kind, typeinfo_address, module, class_flags, vtables
//   [INHERITANCE]  tab-separated: derived, base_index, base, virtual, access,
//                  offset, offset_flags
//                  (one line per direct base, so multiple inheritance is
//                   represented exactly, in declaration order; virtuality,
//                   access and offset come from __base_class_type_info)
//   [VTABLES]      tab-separated: class, kind, derived_owner, group_index,
//                  sub_index, head, address_point, offset_to_top, header_kind,
//                  header_count, header_vbase_words, header_words, slot_index,
//                  entry, name, provenance
//                  (one line per vtable slot. A class's typeinfo is carried by
//                   its own vtable AND by every construction vtable ARMCC
//                   emitted for a class deriving from it, so rows are grouped
//                   and tagged with kind rather than all being treated as
//                   sub-vtables of one class)
//   [VTT]          tab-separated: owner, vtt_address, entry_index, entry,
//                  target_class, target_kind, target_offset
//   [TREE]         indented tree from every root; a class with several bases
//                  appears under each of them. Repeat appearances are marked
//                  [dup] and are not expanded again.
//
// @category RTTI
// @author AlgebraManiacABC

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

import util.BaseRef;
import util.Demangler;
import util.VtableScan;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;

public class ExportClassHierarchy extends GhidraScript {

    private static final int PTR_SIZE = 4;

    // __base_class_type_info::__offset_flags masks (Itanium C++ ABI 2.9.5.6.3)
    private static final int VIRTUAL_MASK = 0x1;
    private static final int PUBLIC_MASK = 0x2;
    private static final int OFFSET_SHIFT = 8;

    // __vmi_class_type_info::__flags masks (Itanium C++ ABI 2.9.5.6.4)
    private static final int NON_DIAMOND_REPEAT_MASK = 0x1;
    private static final int DIAMOND_SHAPED_MASK = 0x2;

    /** One direct base, with its __offset_flags decoded. */
    private static class BaseInfo {
        final String name;
        final boolean isVirtual;
        final boolean isPublic;
        final int offset;       // signed; for a virtual base this is the vbase offset offset
        final int offsetFlags;  // raw field, 0 when synthesized

        BaseInfo(String name, int offsetFlags) {
            this.name = name;
            this.offsetFlags = offsetFlags;
            this.isVirtual = (offsetFlags & VIRTUAL_MASK) != 0;
            this.isPublic = (offsetFlags & PUBLIC_MASK) != 0;
            this.offset = offsetFlags >> OFFSET_SHIFT;   // arithmetic: offsets may be negative
        }

        /** Short human-readable form used in the tree, e.g. "virtual, +0x10". */
        String describe() {
            StringBuilder sb = new StringBuilder();
            if (isVirtual) sb.append("virtual, ");
            if (!isPublic) sb.append("non-public, ");
            sb.append(offset < 0 ? "-0x" + Integer.toHexString(-offset)
                                 : "+0x" + Integer.toHexString(offset));
            return sb.toString();
        }
    }

    private static class ClassInfo {
        String fullName;        // e.g. nn::foo::Bar
        String namespaceName;   // e.g. nn::foo   ("" if global)
        String simpleName;      // e.g. Bar
        String rttiKind = "?";  // __class_type_info / __si_class_type_info / ...
        String typeinfoAddr = "";
        String module;          // program the typeinfo lives in
        String classFlags = ""; // __vmi_class_type_info::__flags, decoded
        final List<BaseInfo> bases = new ArrayList<>();

        ClassInfo(String fullName, String module) {
            this.fullName = fullName;
            this.module = module;
            int idx = lastTopLevelSeparator(fullName);
            this.namespaceName = (idx < 0) ? "" : fullName.substring(0, idx);
            this.simpleName = (idx < 0) ? fullName : fullName.substring(idx + 2);
        }
    }

    /**
     * Index of the last "::" that is not inside template arguments, so
     * BsPartsSaveMgr&lt;svholder::Mail&gt; splits as namespace "" / simple name
     * "BsPartsSaveMgr&lt;svholder::Mail&gt;" rather than at the inner "::".
     * Returns -1 when the name has no enclosing namespace.
     */
    private static int lastTopLevelSeparator(String name) {
        int depth = 0;
        int last = -1;
        int i = 0;
        while (i < name.length()) {
            char c = name.charAt(i);

            // An "operator" name carries angle brackets of its own (operator<,
            // operator>>, operator->); skip its symbol run so it cannot unbalance
            // the template depth.
            if (c == 'o' && name.startsWith("operator", i)
                    && (i == 0 || !isNameChar(name.charAt(i - 1)))) {
                i += "operator".length();
                while (i < name.length() && OPERATOR_CHARS.indexOf(name.charAt(i)) >= 0) i++;
                continue;
            }

            if (c == '<') {
                depth++;
            } else if (c == '>') {
                if (depth > 0) depth--;
            } else if (c == ':' && depth == 0
                    && i + 1 < name.length() && name.charAt(i + 1) == ':') {
                last = i;
                i += 2;
                continue;
            }
            i++;
        }
        return last;
    }

    private static final String OPERATOR_CHARS = "<>=!+-*/%^&|~,()[] ";

    private static boolean isNameChar(char c) {
        return Character.isLetterOrDigit(c) || c == '_' || c == '$';
    }

    // full class name -> info
    private final Map<String, ClassInfo> classes = new LinkedHashMap<>();
    // program name -> (typeinfo address -> class name)
    private final Map<String, Map<Long, String>> typeinfoByProgram = new HashMap<>();
    // class name -> program its typeinfo was found in
    private final Map<String, Program> classProgram = new HashMap<>();
    // class name -> typeinfo offset
    private final Map<String, Long> classTypeinfoAddr = new HashMap<>();

    private final Map<String, Program> importedPrograms = new HashMap<>();
    private final Set<String> resolved = new HashSet<>();

    // class name -> the vtable groups carrying its typeinfo, in address order. A class has
    // at most one group that is its own vtable; the rest are construction vtables emitted
    // for classes that derive from it.
    private final Map<String, List<VtableScan.VtableGroup>> vtablesByClass =
            new LinkedHashMap<>();
    // typeinfo offset -> struct size, for excluding typeinfo bodies from the vtable scan
    private final Map<Long, Integer> typeinfoSizes = new HashMap<>();

    private VtableScan scan;

    @Override
    protected void run() throws Exception {
        export(askFile("Export class hierarchy to", "Save"));
    }

    /**
     * The whole export for currentProgram, to the given file. Public so CROLink can run it
     * on programs it still holds unsaved; set this script up with a state whose current
     * program is code.bin first.
     */
    public void export(File outFile) throws Exception {
        export(outFile, List.of());
    }

    /**
     * As {@link #export(File)}, with {@code modules} registered up front rather than only
     * when an import record leads to them. ACNL's static.crs imports from every CRO, so
     * code.bin's external libraries reached them all; MLDT's imports from none, and the
     * export written from code.bin alone had not one CRO class in it.
     */
    public void export(File outFile, List<Program> modules) throws Exception {
        try {
            collectTypeinfoSymbols(currentProgram);
            for (Program p : modules) {
                if (p == currentProgram) continue;
                String path = p.getDomainFile().getPathname();
                if (importedPrograms.containsKey(path)) continue;
                // Held like a program openCroProgram opened, so the release in finally
                // gives back exactly what was taken.
                p.addConsumer(this);
                importedPrograms.put(path, p);
                collectTypeinfoSymbols(p);
            }

            // Resolve bases for everything found in the current program;
            // external resolution may pull in further modules as it goes.
            // Until nothing new turns up. Opening a CRO registers every typeinfo in it, and
            // a single pass over the starting snapshot never came back for those: all 407
            // CRO-only classes were written with the "?" they start with, never tried.
            boolean grew = true;
            while (grew && !monitor.isCancelled()) {
                grew = false;
                for (String name : new ArrayList<>(classes.keySet())) {
                    if (monitor.isCancelled()) break;
                    if (resolved.contains(name)) continue;
                    grew = true;
                    try {
                        resolveBases(name);
                    } catch (Exception e) {
                        println("    WARNING: could not resolve bases of " + name + ": "
                                + e.getMessage());
                        unresolvedBases.add(name);
                    }
                }
            }

            addClassesWithoutRTTI();
            dedupeBases();
            collectVtables();

            try (PrintWriter out = new PrintWriter(new FileWriter(outFile))) {
                write(out);
            }
            int subVtables = 0;
            for (List<VtableScan.VtableGroup> gs : vtablesByClass.values()) {
                for (VtableScan.VtableGroup g : gs) subVtables += g.subs().size();
            }
            println("Wrote " + classes.size() + " classes, " + vtablesByClass.size() +
                    " with vtables (" + subVtables + " sub-vtables), to " +
                    outFile.getAbsolutePath());
        } finally {
            // Everything in this map came from getDomainObject, which takes a consumer
            // reference whoever the program turns out to be -- the tool's current program
            // included, when a cross-module reference leads back to it. Excluding that one,
            // as this used to, gave back one fewer reference than were taken and left a
            // leaked consumer behind on every run. Releasing closes nothing: the tool holds
            // its own reference to the program it has open.
            for (Program p : importedPrograms.values()) {
                if (p == null) continue;
                try {
                    p.release(this);
                } catch (Exception e) {
                    printerr("Could not release " + p.getName() + ": " + e.getMessage());
                }
            }
            importedPrograms.clear();
        }
    }

    // ---------------------------------------------------------------
    //  Collection
    // ---------------------------------------------------------------

    /** Register every "typeinfo" symbol in the given program as a class. */
    private void collectTypeinfoSymbols(Program program) {
        Map<Long, String> byAddr =
                typeinfoByProgram.computeIfAbsent(program.getName(), k -> new HashMap<>());

        SymbolIterator iter = program.getSymbolTable().getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            if (!sym.getName().equals("typeinfo")) continue;
            // An imported typeinfo (a named import of _ZTI..., demangled into
            // |static|::X::typeinfo) has an external-space address, not one in this
            // program's memory; the class is registered from the module that defines it.
            if (sym.isExternal()) continue;

            Namespace ns = sym.getParentNamespace();
            if (ns == null || ns.isGlobal()) continue;

            String className = ns.getName(true);
            if (className.startsWith("__cxxabiv1")) continue;

            long addr = sym.getAddress().getOffset();
            byAddr.putIfAbsent(addr, className);

            if (!classes.containsKey(className)) {
                ClassInfo info = new ClassInfo(className, program.getName());
                info.typeinfoAddr = String.format("0x%08x", addr);
                classes.put(className, info);
                classProgram.put(className, program);
                classTypeinfoAddr.put(className, addr);
            }
        }
    }

    /**
     * Classes that exist as namespaces but never got a typeinfo symbol still
     * belong in the export; they simply have no known bases.
     */
    private void addClassesWithoutRTTI() {
        Iterator<GhidraClass> iter = currentProgram.getSymbolTable().getClassNamespaces();
        while (iter.hasNext()) {
            GhidraClass gc = iter.next();
            String name = gc.getName(true);
            if (name.startsWith("__cxxabiv1")) continue;
            if (classes.containsKey(name)) continue;

            ClassInfo info = new ClassInfo(name, currentProgram.getName());
            info.rttiKind = "no_rtti";
            classes.put(name, info);
        }
    }

    /**
     * Drop exact duplicate edges (same base, same __offset_flags). Repeated
     * non-virtual bases at different offsets are genuinely distinct subobjects
     * and are kept.
     */
    private void dedupeBases() {
        for (ClassInfo info : classes.values()) {
            Set<List<Object>> seen = new HashSet<>();
            List<BaseInfo> unique = new ArrayList<>();
            for (BaseInfo b : info.bases) {
                if (seen.add(List.of(b.name, b.offsetFlags))) unique.add(b);
            }
            info.bases.clear();
            info.bases.addAll(unique);
        }
    }

    // ---------------------------------------------------------------
    //  Base class resolution (mirrors util.RenameVTableFunctions)
    // ---------------------------------------------------------------

    private void resolveBases(String className) throws Exception {
        if (!resolved.add(className)) return;
        // The ABI's own classes are never a game class's base, and their names fool the
        // name-based kind fallback below: __cxxabiv1::__vmi_class_type_info "contains
        // vmi_class", was read as a vmi typeinfo, and walked hundreds of garbage words as
        // its bases until it ran off the end of memory. collectTypeinfoSymbols has always
        // skipped them; the cross-module paths reach them another way.
        if (className.startsWith("__cxxabiv1")) return;

        Program program = classProgram.get(className);
        Long tiOffset = classTypeinfoAddr.get(className);
        if (program == null || tiOffset == null) return;

        ClassInfo info = classes.get(className);
        Address addr = program.getAddressFactory()
                .getDefaultAddressSpace().getAddress(tiOffset);

        // A typeinfo's first word points at one of exactly three shared ABI vtables, and
        // which one it is *is* the kind. That is a property of the bytes, so it holds
        // whether or not anything has applied a struct here yet; the applied length below
        // only repeats it, and repeats it wrongly whenever the struct is stale or absent.
        // In a CRO the import record decides, and before this program's own statistics.
        // A CRO's data segment is all zeros in the file -- every word, the ABI vtable word
        // included, is written by a relocation -- so the statistics there sort typeinfos by
        // relocated values they cannot see the meaning of. In ModuleMiniGame0 that called
        // 8-byte __class_type_info typeinfos "__si", and 19 of them read the next
        // typeinfo's ABI vtable word as their base.
        String rttiKind = null;
        if (program == currentProgram) {
            rttiKind = abiVtableKinds(program).get(wordAt(program, tiOffset));
        }

        if (rttiKind == null && program != currentProgram) {
            // In a CRO the ABI vtable word is an import from the static module, so its kind
            // is decided where the three vtables are: follow the import record and ask
            // code.bin. This is what lets a CRO class's own base be read at all, rather than
            // its ancestry stopping dead at "?".
            ExternalTarget t = externalTarget(program, addr);
            if (t != null) {
                Map<Long, String> kinds = abiVtableKinds(t.program());
                rttiKind = kinds.get(t.offset());
                if (rttiKind == null) rttiKind = kinds.get(t.offset() + 8);
                if (rttiKind != null) kindsByImport++;
            }
            // No import record on the word: the module's own statistics, as before.
            if (rttiKind == null) {
                rttiKind = abiVtableKinds(program).get(wordAt(program, tiOffset));
            }
        }
        if (rttiKind == null) {
            // The applied length, but only from a struct somebody applied deliberately.
            // An undefined or default-sized data item here is not evidence of anything,
            // and reading one as a length said AcStrc (typeinfo 0x90824, in
            // ModuleOutdoor.cro, where the ABI vtables were never identified) is a
            // __class_type_info -- "no bases" -- when its derived classes plainly inherit
            // DemoActor and Actor slots. That false certainty truncates the ancestry and
            // accounts for 78 of the 126 out-of-ancestry slot names. Unknown is the honest
            // answer, and it is what 407 other CRO typeinfos already get.
            // And only in the program being exported. A struct applied in a CRO is one
            // somebody applied there in an earlier session, on evidence this run does not
            // have and cannot check -- AcStrc's typeinfo at 0x90824 in ModuleOutdoor.cro
            // carries an 8-byte one, which read back as "__class_type_info: no bases"
            // while its derived classes plainly inherit DemoActor and Actor slots. A
            // typeinfo in a CRO is unknown unless its ABI vtable word says otherwise.
            Data data = (program == currentProgram)
                    ? program.getListing().getDataAt(addr) : null;
            if (data != null && data.isDefined()
                    && data.getDataType() instanceof Structure) {
                int size = data.getLength();
                if (size == 8) rttiKind = "__class_type_info";
                else if (size == 12) rttiKind = "__si_class_type_info";
                else if (size >= 16) rttiKind = "__vmi_class_type_info";
            }
        }
        if (rttiKind == null) {
            if (className.contains("vmi_class")) rttiKind = "__vmi_class_type_info";
            else if (className.contains("si_class")) rttiKind = "__si_class_type_info";
            else if (className.contains("class_type")) rttiKind = "__class_type_info";
        }
        if (rttiKind == null) {
            println("    WARNING: Could not determine RTTI type for " + className +
                    " at " + addr + " in " + program.getName());
            // "?" rather than "unknown", so a typeinfo this run could not read looks the
            // same however it failed -- the 407 never reached and this one, tried and
            // undecidable, are the same fact to anything reading the export.
            info.rttiKind = "?";
            return;
        }
        info.rttiKind = rttiKind;

        boolean isCurrent = (program == currentProgram);

        switch (rttiKind) {
            case "__class_type_info" -> {
                if (isCurrent) typeinfoSizes.put(tiOffset, 8);
            }
            // A __si base is always public, non-virtual, at offset 0; synthesize
            // the equivalent __offset_flags so every edge is uniformly described.
            case "__si_class_type_info" -> {
                if (isCurrent) typeinfoSizes.put(tiOffset, 12);
                resolveBase(program, addr.add(8), info, PUBLIC_MASK);
            }
            case "__vmi_class_type_info" -> {
                // Checked before it is trusted. Now that CRO classes are resolved too, a
                // kind can come from an import record rather than from this program's own
                // statistics, and one read wrong made a count out of an arbitrary word and
                // walked off the end of memory (0x944bf8), killing the whole export.
                Long flags = wordAt(program, addr.getOffset() + 8);
                Long count = wordAt(program, addr.getOffset() + 12);
                if (flags == null || count == null || flags > 3 || count < 1 || count > 64) {
                    println(String.format("    WARNING: %s at %s in %s reads as "
                            + "__vmi_class_type_info but its flags/base count (%s/%s) are "
                            + "not; left unknown", className, addr, program.getName(),
                            flags, count));
                    info.rttiKind = "?";
                    return;
                }
                info.classFlags = describeClassFlags(flags.intValue());
                int baseCount = count.intValue();
                if (isCurrent) typeinfoSizes.put(tiOffset, 16 + 8 * baseCount);
                for (int b = 0; b < baseCount; b++) {
                    Address baseEntry = addr.add(16 + b * 8L);
                    // __base_class_type_info = { const __class_type_info *__base_type;
                    //                            long __offset_flags; }
                    Long offsetFlags = wordAt(program, baseEntry.getOffset() + 4);
                    if (offsetFlags == null) {
                        unresolvedBases.add(className);
                        break;
                    }
                    resolveBase(program, baseEntry, info, offsetFlags.intValue());
                }
            }
        }
    }

    // program name -> (__cxxabiv1 vtable address point -> which of the three it is)
    private final Map<String, Map<Long, String>> abiVtableKinds = new HashMap<>();

    /** Fewer users than this and a group's shape statistics prove nothing. */
    private static final int MIN_ABI_USERS_TO_CLASSIFY = 4;

    /** Share of a group's users that must agree before its kind is called. */
    private static final double ABI_KIND_MAJORITY = 0.6;

    /**
     * Sort this program's typeinfo structures by the ABI vtable they name, and work out
     * which of the three each of those vtables is -- from structure alone, with no symbol,
     * no name string and nothing applied.
     *
     * <p>A {@code __vmi_class_type_info} carries a small flags word, a small base count and
     * that many base entries, each naming another typeinfo; nothing else reads that way.
     * A {@code __si_class_type_info} is 12 bytes whose word 2 is its one base's typeinfo,
     * so its users overwhelmingly point at a typeinfo there. Whatever is left is
     * {@code __class_type_info}, which is 8 bytes and says nothing beyond its name.
     *
     * <p>Groups too small to judge are left out rather than guessed at, and the caller
     * falls back to the applied struct length for those.
     */
    private Map<Long, String> abiVtableKinds(Program program) {
        Map<Long, String> cached = abiVtableKinds.get(program.getName());
        if (cached != null) return cached;

        Map<Long, String> result = new HashMap<>();
        abiVtableKinds.put(program.getName(), result);

        Map<Long, String> tis = typeinfoByProgram.get(program.getName());
        if (tis == null || tis.isEmpty()) return result;
        Set<Long> tiAddrs = tis.keySet();

        Map<Long, List<Long>> users = new LinkedHashMap<>();
        for (long ti : tiAddrs) {
            Long first = wordAt(program, ti);
            if (first == null) continue;
            users.computeIfAbsent(first, k -> new ArrayList<>()).add(ti);
        }

        Set<String> taken = new HashSet<>();
        // Most-used first, so if two groups somehow both read as __si the bigger one --
        // which is always the real one -- takes the name.
        List<Map.Entry<Long, List<Long>>> ranked = new ArrayList<>(users.entrySet());
        ranked.sort((a, b) -> Integer.compare(b.getValue().size(), a.getValue().size()));

        for (Map.Entry<Long, List<Long>> group : ranked) {
            List<Long> members = group.getValue();
            if (members.size() < MIN_ABI_USERS_TO_CLASSIFY) continue;

            int vmi = 0, si = 0;
            for (long ti : members) {
                if (readsAsVmi(program, tiAddrs, ti)) vmi++;
                else if (namesATypeinfo(program, tiAddrs, ti + 8)) si++;
            }
            double n = members.size();
            String kind = null;
            if (vmi / n >= ABI_KIND_MAJORITY) kind = "__vmi_class_type_info";
            else if (si / n >= ABI_KIND_MAJORITY) kind = "__si_class_type_info";
            // "__class_type_info" is what is left over, not what was recognised -- and
            // leftover is only meaningful when the two positive tests had a fair chance.
            // Both need the *base* typeinfo to be one this program knows, so in a CRO,
            // where only the handful reached through external references is known, an
            // ordinary __si class whose base lives in code.bin reads as neither and lands
            // here by default. That is how AcStrc came out as "no bases" while its derived
            // classes plainly inherit DemoActor and Actor slots, truncating an ancestry and
            // driving 29 of the 126 out-of-ancestry slot names. A typeinfo in another
            // module is left unknown; vmi and si are positive findings and still count.
            else if (program == currentProgram) kind = "__class_type_info";

            if (kind != null && taken.add(kind)) result.put(group.getKey(), kind);
        }
        return result;
    }

    /** True when the word at {@code at} points at a typeinfo this program knows. */
    private boolean namesATypeinfo(Program program, Set<Long> tiAddrs, long at) {
        Long ptr = wordAt(program, at);
        return ptr != null && tiAddrs.contains(ptr);
    }

    /** True when the structure at {@code ti} reads as a {@code __vmi_class_type_info}. */
    private boolean readsAsVmi(Program program, Set<Long> tiAddrs, long ti) {
        Long flags = wordAt(program, ti + 8);
        Long count = wordAt(program, ti + 12);
        if (flags == null || count == null) return false;
        if (flags > 3) return false;                    // only bits 0 and 1 are defined
        if (count < 1 || count > 64) return false;
        for (long b = 0; b < count; b++) {
            if (!namesATypeinfo(program, tiAddrs, ti + 16 + 8 * b)) return false;
        }
        return true;
    }

    /** The word at {@code at}, unsigned, or null when nothing is mapped there. */
    private Long wordAt(Program program, long at) {
        try {
            Address a = program.getAddressFactory().getDefaultAddressSpace().getAddress(at);
            return Integer.toUnsignedLong(program.getMemory().getInt(a));
        } catch (Exception e) {
            return null;
        }
    }

    private static String describeClassFlags(int flags) {
        List<String> parts = new ArrayList<>();
        if ((flags & NON_DIAMOND_REPEAT_MASK) != 0) parts.add("non_diamond_repeat");
        if ((flags & DIAMOND_SHAPED_MASK) != 0) parts.add("diamond_shaped");
        if (parts.isEmpty()) parts.add("none");
        return String.format("0x%x(%s)", flags, String.join("|", parts));
    }

    private void resolveBase(Program program, Address baseFieldAddr, ClassInfo child,
                             int offsetFlags) throws Exception {
        Long word = wordAt(program, baseFieldAddr.getOffset());
        if (word == null) {
            println("    WARNING: base field of " + child.fullName + " at " + baseFieldAddr
                    + " is unreadable");
            unresolvedBases.add(child.fullName);
            return;
        }
        long basePtr = word;

        String baseName = typeinfoByProgram
                .getOrDefault(program.getName(), Collections.emptyMap())
                .get(basePtr);
        if (baseName != null) {
            child.bases.add(new BaseInfo(baseName, offsetFlags));
            resolveBases(baseName);
            return;
        }

        // Whatever the word holds, an import record on it is what says where the base
        // lives. Gating this on the word pointing at a symbol called "OnUnresolved" tied
        // every cross-module edge to one name the pipeline is trying to get rid of: the
        // run that finally renames the handler would have cut them all.
        ExternalTypeinfoResult result = resolveExternalTypeinfo(program, baseFieldAddr);
        if (result != null) {
            if (!registerExternal(result)) {
                println("    WARNING: base field of " + child.fullName + " at " + baseFieldAddr
                        + " leads to " + result.className + ", which is not a class");
                unresolvedBases.add(child.fullName);
                return;
            }
            child.bases.add(new BaseInfo(result.className, offsetFlags));
            resolveBases(result.className);
            return;
        }

        // A base in the same module that nothing has labelled -- the normal state of a CRO
        // on a clean project. Its _ZTS string names it; only tried once the import record
        // has had its say, because an imported word holds another module's address and
        // reads as garbage here.
        if (basePtr != 0 && program != currentProgram) {
            try {
                Address local = addr(program, basePtr);
                String name = Demangler.classNameOfTypeinfo(program, local);
                if (name != null && registerExternal(makeResult(program, basePtr, name))) {
                    child.bases.add(new BaseInfo(name, offsetFlags));
                    resolveBases(name);
                    localByBytes++;
                    return;
                }
            } catch (Exception e) {
                // Not an address in this module.
            }
        }

        if (basePtr == 0 || isOnUnresolved(program, basePtr)) {
            println("    WARNING: Could not resolve external base for " +
                    child.fullName + " at " + baseFieldAddr);
            unresolvedBases.add(child.fullName);
            return;
        }

        println("    WARNING: Unknown base typeinfo pointer 0x" +
                Long.toHexString(basePtr) + " for " + child.fullName);
        unresolvedBases.add(child.fullName);
    }

    /** Classes with a base this run could not name: their ancestry is known to be cut. */
    private final Set<String> unresolvedBases = new HashSet<>();

    /** False, and nothing registered, when the result is one of the ABI's own classes. */
    private boolean registerExternal(ExternalTypeinfoResult result) {
        if (result.className.startsWith("__cxxabiv1")) {
            abiClassesReached++;
            return false;
        }
        typeinfoByProgram
                .computeIfAbsent(result.program.getName(), k -> new HashMap<>())
                .putIfAbsent(result.typeinfoAddr, result.className);

        if (!classes.containsKey(result.className)) {
            ClassInfo info = new ClassInfo(result.className, result.program.getName());
            info.typeinfoAddr = String.format("0x%08x", result.typeinfoAddr);
            classes.put(result.className, info);
        }
        classProgram.putIfAbsent(result.className, result.program);
        classTypeinfoAddr.putIfAbsent(result.className, result.typeinfoAddr);
        return true;
    }

    /** Base lookups that landed on a __cxxabiv1 class: a misread field, never a real base. */
    private int abiClassesReached = 0;

    private boolean isOnUnresolved(Program program, long addr) {
        Address realAddr = program.getMinAddress().getAddressSpace().getAddress(addr);
        Symbol[] syms = program.getSymbolTable().getSymbols(realAddr);
        return syms != null && syms.length > 0 && syms[0].getName().equals("OnUnresolved");
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
            ProjectData projectData = getState().getProject().getProjectData();
            DomainFile domainFile = projectData.getFile(progPath);
            if (domainFile == null) {
                println("    WARNING: Could not find CRO program: " + progPath);
                importedPrograms.put(progPath, null);
                return null;
            }
            Program prog = (Program) domainFile.getDomainObject(this, true, false, monitor);
            importedPrograms.put(progPath, prog);
            // Separate catch from the open above: sharing one meant a failure while
            // reading the symbols overwrote the map entry with null, dropping the only
            // reference to a program this script holds a consumer on.
            try {
                collectTypeinfoSymbols(prog);
            } catch (Exception e) {
                println("    WARNING: Could not read typeinfo from " + progPath + ": "
                        + e.getMessage() + " (program stays open until release)");
            }
            return prog;
        } catch (Exception e) {
            println("    ERROR: Could not open CRO program " + progPath + ": " + e.getMessage());
            importedPrograms.put(progPath, null);
            return null;
        }
    }

    private ExternalTypeinfoResult resolveExternalTypeinfo(Program sourceProgram, Address refAddr) {
        Reference[] refs = sourceProgram.getReferenceManager().getReferencesFrom(refAddr);

        for (Reference ref : refs) {
            if (!(ref instanceof ExternalReference extRef)) continue;
            ExternalLocation extLoc = extRef.getExternalLocation();

            Library imported = sourceProgram.getExternalManager()
                    .getExternalLibrary(extLoc.getLibraryName());
            if (imported == null) continue;
            String progPath = imported.getAssociatedProgramPath();
            if (progPath == null) continue;

            Program croProg = openCroProgram(progPath);
            if (croProg == null) continue;

            Address extAddr = extLoc.getAddress();
            if (extAddr == null) continue;

            Address croAddr = croProg.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(extAddr.getOffset());

            for (Symbol sym : croProg.getSymbolTable().getSymbols(croAddr)) {
                if (!sym.getName().equals("typeinfo")) continue;
                Namespace ns = sym.getParentNamespace();
                if (ns != null && !ns.isGlobal()) {
                    return makeResult(croProg, croAddr.getOffset(), ns.getName(true));
                }
            }

            // Fallback: follow the RTTI name pointer and use its namespace.
            try {
                long namePtr = Integer.toUnsignedLong(croProg.getMemory().getInt(croAddr.add(4)));
                Address namePtrAddr = croProg.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(namePtr);
                for (Symbol sym : croProg.getSymbolTable().getSymbols(namePtrAddr)) {
                    Namespace ns = sym.getParentNamespace();
                    if (ns != null && !ns.isGlobal()) {
                        return makeResult(croProg, croAddr.getOffset(), ns.getName(true));
                    }
                }
            } catch (Exception e) {
                println("WARNING: Could not read CRO typeinfo at " + croAddr + " in " + progPath);
            }

            // Last: the _ZTS string itself. Both routes above need the CRO to carry labels,
            // which a freshly imported one does not until the pipeline's changes to it are
            // saved -- and a clean run left five code.bin classes rootless that way.
            String fromBytes = Demangler.classNameOfTypeinfo(croProg, croAddr);
            if (fromBytes != null) {
                externalByBytes++;
                return makeResult(croProg, croAddr.getOffset(), fromBytes);
            }
        }
        return null;
    }

    /** External bases named from their _ZTS string, with no label in the CRO. */
    private int externalByBytes = 0;
    /** Same-module CRO bases named from their _ZTS string. */
    private int localByBytes = 0;
    /** CRO typeinfo kinds read through the import of code.bin's ABI vtable. */
    private int kindsByImport = 0;

    private record ExternalTarget(Program program, long offset) {}

    /**
     * Where the import record on a word leads: the exporting program and the offset in it.
     * Null when there is no record, or its module cannot be opened.
     */
    private ExternalTarget externalTarget(Program source, Address at) {
        for (Reference ref : source.getReferenceManager().getReferencesFrom(at)) {
            if (!(ref instanceof ExternalReference extRef)) continue;
            ExternalLocation loc = extRef.getExternalLocation();
            Address extAddr = loc.getAddress();
            if (extAddr == null) continue;
            Library lib = source.getExternalManager().getExternalLibrary(loc.getLibraryName());
            if (lib == null || lib.getAssociatedProgramPath() == null) continue;
            Program target = openCroProgram(lib.getAssociatedProgramPath());
            if (target == null) continue;
            return new ExternalTarget(target, extAddr.getOffset());
        }
        return null;
    }

    private static Address addr(Program program, long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private ExternalTypeinfoResult makeResult(Program prog, long tiAddr, String className) {
        ExternalTypeinfoResult result = new ExternalTypeinfoResult();
        result.program = prog;
        result.typeinfoAddr = tiAddr;
        result.className = className;
        return result;
    }

    // ---------------------------------------------------------------
    //  VTable discovery
    // ---------------------------------------------------------------

    /**
     * Hand the current program to {@link VtableScan}, which groups sub-tables into whole
     * _ZTV objects, derives each head over its virtual-base header words, and separates
     * the class's own vtable from the construction vtables ARMCC emits under its typeinfo.
     *
     * Read-only: unlike the rename pipeline, nothing is applied to the program.
     */
    private void collectVtables() throws Exception {
        Map<Long, String> byAddr = typeinfoByProgram.get(currentProgram.getName());
        if (byAddr == null || byAddr.isEmpty()) return;

        scan = new VtableScan(currentProgram, byAddr, typeinfoSizes, baseRefs(),
                this::println, monitor);
        scan.scan();
        scan.printSummary();

        for (VtableScan.VtableGroup group : scan.groups()) {
            vtablesByClass.computeIfAbsent(group.className(), k -> new ArrayList<>())
                    .add(group);
        }
    }

    /** The inheritance edges VtableScan needs, in the shared util form. */
    private Map<String, List<BaseRef>> baseRefs() {
        Map<String, List<BaseRef>> out = new HashMap<>();
        for (Map.Entry<String, ClassInfo> e : classes.entrySet()) {
            List<BaseRef> refs = new ArrayList<>();
            for (BaseInfo b : e.getValue().bases) {
                // A __si base carries no flags word; resolveBases already synthesized
                // PUBLIC_MASK for it, so every edge reads the same way here too.
                refs.add(new BaseRef(b.name, b.offsetFlags != 0 ? b.offsetFlags
                        : (b.isPublic ? BaseRef.PUBLIC_MASK : 0)));
            }
            if (!refs.isEmpty()) out.put(e.getKey(), refs);
        }
        return out;
    }

    /** The vbase-offset words as a comma-separated list, or "-" when there are none. */
    /**
     * Whether a slot's name is one armcc could have emitted, or this pipeline's stand-in.
     *
     * <p>A {@code VF<nn>} name carries exactly one fact -- which slot the function sits in
     * -- and the method's real name is not among them. Marking it keeps a consumer from
     * treating {@code AcNpcSpShop::VF30} as a recovered symbol simply because it is
     * spelled like one.
     */
    private static String provenanceOf(String entryName) {
        if (entryName == null || entryName.isEmpty()) return "none";
        String leaf = entryName;
        int sep = leaf.lastIndexOf("::");
        if (sep >= 0) leaf = leaf.substring(sep + 2);
        if (leaf.startsWith("FUN_") || leaf.startsWith("LAB_")) return "none";
        return SLOT_PLACEHOLDER.matcher(leaf).matches() ? "placeholder" : "recovered";
    }

    /** Same spelling RenameVTableFunctions hands out; kept in step with it by hand. */
    private static final java.util.regex.Pattern SLOT_PLACEHOLDER =
            java.util.regex.Pattern.compile("V?F\\d{2,}(_.*)?");

    private static String joinInts(int[] values) {
        if (values == null || values.length == 0) return "-";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < values.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(values[i]);
        }
        return sb.toString();
    }

    /** Best available name for a vtable entry. */
    private String describeEntry(Address slotAddr, long value) {
        if (value == 0) {
            for (Reference ref :
                    currentProgram.getReferenceManager().getReferencesFrom(slotAddr)) {
                if (ref instanceof ExternalReference extRef) {
                    ExternalLocation loc = extRef.getExternalLocation();
                    String label = loc.getLabel();
                    if (label != null && !label.isEmpty()) {
                        return loc.getLibraryName() + "::" + label;
                    }
                }
            }
            return "";
        }

        Address target;
        try {
            target = currentProgram.getMinAddress()
                    .getAddressSpace().getAddress(value & ~1L);
        } catch (Exception e) {
            return "";
        }

        String demangled = demangledNameAt(target);
        if (demangled != null) return demangled;

        Function func = currentProgram.getFunctionManager().getFunctionAt(target);
        if (func != null) return func.getName(true);

        Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(target);
        return (sym != null) ? sym.getName(true) : "";
    }

    /**
     * The readable name at an address, whichever symbol happens to be primary.
     *
     * <p>Both spellings sit on the same address -- {@code _ZN5AcFtrD1Ev} beside
     * {@code AcFtr::D1} -- and which one is primary depends on whether ToggleMangledNames
     * was last run. This export is a class hierarchy, so the qualified readable form is
     * the one it always wants; having to flip the program's symbols first to get a usable
     * file made the export depend on program state that has nothing to do with it.
     *
     * <p>Returns null when nothing here is demangled, so the caller keeps its own
     * fallbacks rather than being handed an empty string.
     */
    private String demangledNameAt(Address target) {
        String best = null;
        for (Symbol sym : currentProgram.getSymbolTable().getSymbols(target)) {
            if (sym.getName().startsWith("_Z")) continue;
            if (sym.getSource() == SourceType.DEFAULT) continue;
            String qualified = sym.getName(true);
            // A symbol sitting in a class namespace is the one worth having; a bare global
            // label is only better than nothing.
            if (!sym.getParentNamespace().isGlobal()) return qualified;
            if (best == null) best = qualified;
        }
        return best;
    }

    // ---------------------------------------------------------------
    //  Output
    // ---------------------------------------------------------------

    /** True when the class, or anything it derives from, has an unreadable link. */
    private boolean ancestryIncomplete(String name, Map<String, Boolean> memo,
                                       Set<String> onPath) {
        Boolean known = memo.get(name);
        if (known != null) return known;
        if (!onPath.add(name)) return false;   // a cycle is someone else's report
        ClassInfo c = classes.get(name);
        boolean cut = c == null || "?".equals(c.rttiKind) || unresolvedBases.contains(name);
        if (!cut) {
            for (BaseInfo b : c.bases) {
                if (ancestryIncomplete(b.name, memo, onPath)) { cut = true; break; }
            }
        }
        onPath.remove(name);
        memo.put(name, cut);
        return cut;
    }

    private void write(PrintWriter out) {
        List<String> names = new ArrayList<>(classes.keySet());
        Collections.sort(names);

        out.println("# Class hierarchy for " + currentProgram.getName());
        out.println("# Classes: " + names.size());
        out.println("# Sections: [CLASSES], [INHERITANCE], [VTABLES], [VTT], [TREE]");
        out.println();

        out.println("[CLASSES]");
        out.println("# class_flags is __vmi_class_type_info::__flags (empty for non-vmi classes).");
        out.println("# vtables is the number of vtable groups carrying this class's typeinfo,");
        out.println("# which includes construction vtables emitted for its derived classes;");
        out.println("# see [VTABLES] and filter on kind.");
        out.println("# ancestry is hierarchy_incomplete when this class or any ancestor has a");
        out.println("# typeinfo this run could not read (rtti_kind ?) or a base it could not name;");
        out.println("# its bases, LCAs and slot owners then rest on a cut-off tree. no_rtti classes");
        out.println("# have no typeinfo to read and are not flagged.");
        out.println("# full_name\tnamespace\tsimple_name\trtti_kind\ttypeinfo\tmodule" +
                "\tclass_flags\tvtables\tancestry");
        Map<String, Boolean> incomplete = new HashMap<>();
        int flagged = 0;
        for (String name : names) {
            ClassInfo c = classes.get(name);
            boolean cut = ancestryIncomplete(name, incomplete, new HashSet<>());
            if (cut) flagged++;
            out.printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s%n", c.fullName, c.namespaceName,
                    c.simpleName, c.rttiKind, c.typeinfoAddr, c.module, c.classFlags,
                    vtablesByClass.getOrDefault(name, Collections.emptyList()).size(),
                    cut ? "hierarchy_incomplete" : "complete");
        }
        println(String.format("    Ancestry:               %d classes flagged hierarchy_incomplete; "
                + "CRO bases named from bytes: %d imported, %d same-module; "
                + "CRO typeinfo kinds read through the import: %d; base fields that led to "
                + "an ABI class instead of a base: %d",
                flagged, externalByBytes, localByBytes, kindsByImport, abiClassesReached));
        out.println();

        out.println("[INHERITANCE]");
        out.println("# One line per direct base, in __base_info declaration order.");
        out.println("# virtual/access/offset are decoded from __base_class_type_info::__offset_flags:");
        out.println("#   virtual = __offset_flags & 0x1, public = & 0x2, offset = >> 8 (signed).");
        out.println("# For a virtual base, offset is the offset to the vbase offset in the vtable,");
        out.println("# not the subobject offset. __si bases are always public/non-virtual/0 and are");
        out.println("# reported with a synthesized offset_flags of 0x2.");
        out.println("# derived\tbase_index\tbase\tvirtual\taccess\toffset\toffset_flags");
        for (String name : names) {
            ClassInfo c = classes.get(name);
            for (int i = 0; i < c.bases.size(); i++) {
                BaseInfo b = c.bases.get(i);
                out.printf("%s\t%d\t%s\t%s\t%s\t%d\t0x%08x%n",
                        c.fullName, i, b.name,
                        b.isVirtual ? "virtual" : "nonvirtual",
                        b.isPublic ? "public" : "non-public",
                        b.offset, b.offsetFlags);
            }
        }
        out.println();

        // A name is only "recovered" if armcc could have emitted it. VF30 and its
        // relatives are this pipeline's stand-ins for slots whose method name was never
        // found, and the column exists so a consumer can tell the two apart instead of
        // having to guess from the spelling.
        out.println("[VTABLES]");
        out.println("# One line per vtable slot.");
        out.println("# kind is REAL / REAL_WEAK for the class's own vtable, CONSTRUCTION for a");
        out.println("#   table ARMCC emitted for some other class's constructor (see [VTT]), and");
        out.println("#   ORPHAN for one nothing reaches. REAL_WEAK means no code reference was");
        out.println("#   found but it was the best candidate the class had.");
        out.println("# derived_owner is the class a CONSTRUCTION table was emitted for.");
        out.println("# group_index counts the groups carrying this class's typeinfo; sub_index");
        out.println("#   counts the sub-tables inside one group, 0 being the primary.");
        out.println("# head is where the _ZTV symbol goes: vbase_count offset words, then");
        out.println("#   offset_to_top, then the RTTI slot, then address_point. Do NOT assume");
        out.println("#   address_point == head + 8; virtual bases push it later.");
        out.println("# address_point is the first function slot, i.e. what a this-pointer stores.");
        out.println("# entry is the raw word, thumb bit included; 0 means an external");
        out.println("# reference, whose target is given as name. Only the current program is");
        out.println("# scanned, so bases living in another CRO have no vtable rows here.");
        out.println("# header_kind says what the words before offset_to_top are: vbase for");
        out.println("#   one offset per virtual base, vcall for one per virtual function of");
        out.println("#   a virtual-base subobject, vbase+vcall for a run carrying both, and");
        out.println("#   none when there are no header words. ARMCC's order is");
        out.println("#   [vbase offsets][vcall offsets][offset_to_top][typeinfo], vbase");
        out.println("#   outermost, so header_vbase_words counts from the head and the rest");
        out.println("#   of header_words is the vcall run. A vbase header is not confined to");
        out.println("#   offset_to_top 0: a _ZT_B1_ table led by a class that declares a");
        out.println("#   virtual base carries one too.");
        out.println("# provenance is recovered when the name came from a symbol armcc emitted,");
        out.println("#   and placeholder when it is this pipeline's VF<nn> stand-in for a slot");
        out.println("#   whose method name was never recovered. A placeholder is never mangled.");
        out.println("# class\tkind\tderived_owner\tgroup_index\tsub_index\thead"
                + "\taddress_point\toffset_to_top\theader_kind\theader_count"
                + "\theader_vbase_words\theader_words"
                + "\tslot_index\tentry\tname\tprovenance");
        for (String name : names) {
            List<VtableScan.VtableGroup> groups = vtablesByClass.get(name);
            if (groups == null) continue;
            for (int g = 0; g < groups.size(); g++) {
                VtableScan.VtableGroup group = groups.get(g);
                String owner = (group.derivedOwner() == null) ? "" : group.derivedOwner();
                for (int v = 0; v < group.subs().size(); v++) {
                    VtableScan.SubTable sub = group.subs().get(v);
                    String vbases = joinInts(sub.vbaseOffsets());
                    String headerKind = sub.headerKind();
                    for (int i = 0; i < sub.slots().size(); i++) {
                        long value = sub.slots().get(i);
                        Address slotAddr = sub.addressPoint().add(4L * i);
                        String entryName = describeEntry(slotAddr, value);
                        out.printf("%s\t%s\t%s\t%d\t%d\t0x%08x\t0x%08x\t%d\t%s\t%d\t%d\t%s"
                                        + "\t%d\t0x%08x\t%s\t%s%n",
                                name, group.kind(), owner, g, v,
                                sub.head().getOffset(), sub.addressPoint().getOffset(),
                                sub.offsetToTop(), headerKind, sub.vbaseCount(),
                                sub.vbaseWords(), vbases,
                                i, value, entryName, provenanceOf(entryName));
                    }
                }
            }
        }
        out.println();

        out.println("[VTT]");
        out.println("# One line per VTT entry. A VTT is the flat array of address points a");
        out.println("# constructor walks while building an object with virtual bases; ARMCC");
        out.println("# emits it in a section named after the vtable, so it sits next to the");
        out.println("# owner's group on one side or the other. Entry 0 points at the owner's");
        out.println("# own primary address point; entries into a table carrying a different");
        out.println("# class's typeinfo are that owner's construction vtables.");
        out.println("# owner\tvtt_address\tentry_index\tentry\ttarget_class\ttarget_kind\ttarget_offset");
        if (scan != null) {
            for (VtableScan.Vtt vtt : scan.vtts()) {
                for (int i = 0; i < vtt.entries().size(); i++) {
                    Address entry = vtt.entries().get(i);
                    VtableScan.VtableGroup target = scan.groupAtPoint(entry);
                    String targetClass = (target == null) ? "?" : target.className();
                    String targetKind = (target == null) ? "?" : target.kind().toString();
                    long delta = (target == null) ? 0
                            : entry.getOffset() - target.head().getOffset();
                    out.printf("%s\t0x%08x\t%d\t0x%08x\t%s\t%s\t%d%n",
                            vtt.ownerClass(), vtt.start().getOffset(), i,
                            entry.getOffset(), targetClass, targetKind, delta);
                }
            }
        }
        out.println();

        // children map, for the tree view
        Map<String, List<String>> children = new HashMap<>();
        for (String name : names) {
            for (BaseInfo base : classes.get(name).bases) {
                List<String> kids = children.computeIfAbsent(base.name, k -> new ArrayList<>());
                if (!kids.contains(name)) kids.add(name);
            }
        }
        for (List<String> kids : children.values()) Collections.sort(kids);

        out.println("[TREE]");
        out.println("# A class with multiple bases appears under each of them; each node is");
        out.println("# annotated with the edge to its parent (virtual / non-public / offset) and");
        out.println("# with its remaining bases. Repeats are marked [dup] and are not expanded.");
        Set<String> printed = new HashSet<>();
        for (String name : names) {
            if (classes.get(name).bases.isEmpty()) {
                printNode(out, name, children, printed, new ArrayDeque<>(), "", true);
            }
        }
        // Anything left over sits in an inheritance cycle; emit it so nothing is lost.
        for (String name : names) {
            if (!printed.contains(name)) {
                out.println("# (cycle) unreachable from any root:");
                printNode(out, name, children, printed, new ArrayDeque<>(), "", true);
            }
        }
    }

    private void printNode(PrintWriter out, String name,
                           Map<String, List<String>> children,
                           Set<String> printed, Deque<String> path,
                           String prefix, boolean last) {
        ClassInfo c = classes.get(name);

        StringBuilder line = new StringBuilder();
        if (!prefix.isEmpty()) {
            line.append(prefix).append(last ? "`- " : "|- ");
        }
        line.append(name);

        // Describe the edge from the parent we are printed under, then list the
        // remaining bases with their own flags.
        String parent = path.peek();
        List<BaseInfo> others = new ArrayList<>(c.bases);
        if (parent != null) {
            for (Iterator<BaseInfo> it = others.iterator(); it.hasNext(); ) {
                BaseInfo b = it.next();
                if (b.name.equals(parent)) {
                    line.append("  [").append(b.describe()).append("]");
                    it.remove();
                    break;
                }
            }
        }
        if (!others.isEmpty()) {
            List<String> descs = new ArrayList<>();
            for (BaseInfo b : others) descs.add(b.name + " (" + b.describe() + ")");
            line.append("  (also inherits: ").append(String.join(", ", descs)).append(")");
        }

        boolean cycle = path.contains(name);
        boolean dup = !printed.add(name);
        if (cycle) line.append("  [cycle]");
        else if (dup) line.append("  [dup]");

        out.println(line);
        if (cycle || dup) return;

        List<String> kids = children.getOrDefault(name, Collections.emptyList());
        String childPrefix = prefix.isEmpty() ? "   " : prefix + (last ? "   " : "|  ");
        path.push(name);
        for (int i = 0; i < kids.size(); i++) {
            printNode(out, kids.get(i), children, printed, path,
                    childPrefix, i == kids.size() - 1);
        }
        path.pop();
    }
}
