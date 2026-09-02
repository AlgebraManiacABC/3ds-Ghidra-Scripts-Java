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
//   [VTABLES]      tab-separated: class, sub_index, address_point,
//                  offset_to_top, slot_index, entry, name
//                  (one line per vtable slot; sub_index 0 is the primary
//                   vtable, 1+ are the secondary vtables of a multiply /
//                   virtually inheriting class, in address order)
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
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

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

    /** One sub-vtable: the RTTI slot, its address point, and its function slots. */
    private static class VTableInfo {
        final long rttiSlotAddr;
        final Address addressPoint;
        final int offsetToTop;
        final List<Long> slots = new ArrayList<>();

        VTableInfo(long rttiSlotAddr, Address addressPoint, int offsetToTop) {
            this.rttiSlotAddr = rttiSlotAddr;
            this.addressPoint = addressPoint;
            this.offsetToTop = offsetToTop;
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

    // class name -> sub-vtables, in address order (index 0 = primary)
    private final Map<String, List<VTableInfo>> vtablesByClass = new LinkedHashMap<>();
    // typeinfo offset -> struct size, for excluding typeinfo bodies from the vtable scan
    private final Map<Long, Integer> typeinfoSizes = new HashMap<>();

    @Override
    protected void run() throws Exception {
        File outFile = askFile("Export class hierarchy to", "Save");

        try {
            collectTypeinfoSymbols(currentProgram);

            // Resolve bases for everything found in the current program;
            // external resolution may pull in further modules as it goes.
            for (String name : new ArrayList<>(classes.keySet())) {
                if (monitor.isCancelled()) break;
                resolveBases(name);
            }

            addClassesWithoutRTTI();
            dedupeBases();
            collectVtables();

            try (PrintWriter out = new PrintWriter(new FileWriter(outFile))) {
                write(out);
            }
            int subVtables = 0;
            for (List<VTableInfo> v : vtablesByClass.values()) subVtables += v.size();
            println("Wrote " + classes.size() + " classes, " + vtablesByClass.size() +
                    " with vtables (" + subVtables + " sub-vtables), to " +
                    outFile.getAbsolutePath());
        } finally {
            for (Program p : importedPrograms.values()) {
                if (p != null && p != currentProgram) p.release(this);
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

            Namespace ns = sym.getParentNamespace();
            if (ns == null || ns.isGlobal()) continue;

            String className = ns.getName(true);
            if (className.startsWith("__cxxabiv1")) continue;
            if (ns instanceof Library && !sym.hasReferences()) continue;

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

        Program program = classProgram.get(className);
        Long tiOffset = classTypeinfoAddr.get(className);
        if (program == null || tiOffset == null) return;

        ClassInfo info = classes.get(className);
        Address addr = program.getAddressFactory()
                .getDefaultAddressSpace().getAddress(tiOffset);

        String rttiKind = null;
        Data data = program.getListing().getDataAt(addr);
        if (data != null) {
            int size = data.getLength();
            if (size == 8) rttiKind = "__class_type_info";
            else if (size == 12) rttiKind = "__si_class_type_info";
            else if (size >= 16) rttiKind = "__vmi_class_type_info";
        }
        if (rttiKind == null) {
            if (className.contains("vmi_class")) rttiKind = "__vmi_class_type_info";
            else if (className.contains("si_class")) rttiKind = "__si_class_type_info";
            else if (className.contains("class_type")) rttiKind = "__class_type_info";
        }
        if (rttiKind == null) {
            println("    WARNING: Could not determine RTTI type for " + className +
                    " at " + addr + " in " + program.getName());
            info.rttiKind = "unknown";
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
                info.classFlags = describeClassFlags(program.getMemory().getInt(addr.add(8)));
                int baseCount = program.getMemory().getInt(addr.add(12));
                if (isCurrent) typeinfoSizes.put(tiOffset, 16 + 8 * Math.max(baseCount, 0));
                for (int b = 0; b < baseCount; b++) {
                    Address baseEntry = addr.add(16 + b * 8L);
                    // __base_class_type_info = { const __class_type_info *__base_type;
                    //                            long __offset_flags; }
                    int offsetFlags = program.getMemory().getInt(baseEntry.add(4));
                    resolveBase(program, baseEntry, info, offsetFlags);
                }
            }
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
        Memory progMem = program.getMemory();
        long basePtr = Integer.toUnsignedLong(progMem.getInt(baseFieldAddr));

        String baseName = typeinfoByProgram
                .getOrDefault(program.getName(), Collections.emptyMap())
                .get(basePtr);
        if (baseName != null) {
            child.bases.add(new BaseInfo(baseName, offsetFlags));
            resolveBases(baseName);
            return;
        }

        if (basePtr == 0 || isOnUnresolved(program, basePtr)) {
            ExternalTypeinfoResult result = resolveExternalTypeinfo(program, baseFieldAddr);
            if (result != null) {
                registerExternal(result);
                child.bases.add(new BaseInfo(result.className, offsetFlags));
                resolveBases(result.className);
            } else {
                println("    WARNING: Could not resolve external base for " +
                        child.fullName + " at " + baseFieldAddr);
            }
            return;
        }

        println("    WARNING: Unknown base typeinfo pointer 0x" +
                Long.toHexString(basePtr) + " for " + child.fullName);
    }

    private void registerExternal(ExternalTypeinfoResult result) {
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
    }

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
            collectTypeinfoSymbols(prog);
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
        }
        return null;
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
     * Find every sub-vtable in the current program by locating words that point
     * at a known typeinfo struct (the RTTI slot of a vtable), then walking
     * forward over the function pointers that follow. Only the primary vtable
     * carries a "vtable" label after the rename pipeline, so secondary vtables
     * have to be rediscovered rather than read back from the symbol table.
     *
     * Read-only: unlike the rename pipeline, nothing is applied to the program.
     */
    private void collectVtables() throws Exception {
        Map<Long, String> byAddr = typeinfoByProgram.get(currentProgram.getName());
        if (byAddr == null || byAddr.isEmpty()) return;

        List<Long> rttiSlots = findRttiSlots(byAddr);
        Collections.sort(rttiSlots);

        Memory memory = currentProgram.getMemory();
        AddressSpace space = currentProgram.getMinAddress().getAddressSpace();
        MemoryBlock rodata = findRodataBlock();

        for (int r = 0; r < rttiSlots.size(); r++) {
            if (monitor.isCancelled()) return;

            long slotAddr = rttiSlots.get(r);
            Address slot = space.getAddress(slotAddr);
            long typeinfoAddr = Integer.toUnsignedLong(memory.getInt(slot));
            String className = byAddr.get(typeinfoAddr);
            if (className == null) continue;

            // offset-to-top sits immediately before the RTTI slot; signed.
            int offsetToTop = 0;
            try {
                offsetToTop = memory.getInt(slot.subtract(PTR_SIZE));
            } catch (Exception e) { /* start of block; leave 0 */ }

            // The vtable runs until the next RTTI slot or the end of the block.
            long boundary;
            if (r + 1 < rttiSlots.size()) {
                boundary = rttiSlots.get(r + 1) - PTR_SIZE;   // stop before its offset-to-top
            } else {
                MemoryBlock block = memory.getBlock(slot);
                boundary = (block != null) ? block.getEnd().getOffset() + 1
                        : (rodata != null ? rodata.getEnd().getOffset() + 1
                                          : slotAddr + 0x10000);
            }

            Address addressPoint = null;
            List<Long> slots = new ArrayList<>();
            long current = slotAddr + PTR_SIZE;
            while (current < boundary) {
                Address currentAddr = space.getAddress(current);
                long value;
                try {
                    value = Integer.toUnsignedLong(memory.getInt(currentAddr));
                } catch (Exception e) {
                    break;
                }
                if (!isFunctionPointer(currentAddr, value)) break;

                if (addressPoint == null) addressPoint = currentAddr;
                slots.add(value);
                current += PTR_SIZE;
            }

            if (slots.isEmpty() || addressPoint == null) continue;

            VTableInfo vt = new VTableInfo(slotAddr, addressPoint, offsetToTop);
            vt.slots.addAll(slots);
            vtablesByClass.computeIfAbsent(className, k -> new ArrayList<>()).add(vt);
        }
    }

    /** Words in read-only memory that point at a known typeinfo struct. */
    private List<Long> findRttiSlots(Map<Long, String> byAddr) throws Exception {
        List<Long> found = new ArrayList<>();
        Memory memory = currentProgram.getMemory();
        boolean bigEndian = currentProgram.getLanguage().isBigEndian();

        List<MemoryBlock> blocks = new ArrayList<>();
        MemoryBlock rodata = findRodataBlock();
        if (rodata != null) {
            blocks.add(rodata);
        } else {
            for (MemoryBlock block : memory.getBlocks()) {
                if (block.isInitialized() && block.isRead() && !block.isExecute()) {
                    blocks.add(block);
                }
            }
        }

        for (MemoryBlock block : blocks) {
            if (monitor.isCancelled()) break;
            int size = (int) Math.min(block.getSize(), Integer.MAX_VALUE);
            byte[] bytes = new byte[size];
            int read = block.getBytes(block.getStart(), bytes);
            long base = block.getStart().getOffset();

            for (int i = 0; i + PTR_SIZE <= read; i += PTR_SIZE) {
                long value = readWord(bytes, i, bigEndian);
                if (!byAddr.containsKey(value)) continue;

                long addr = base + i;
                // The body of a typeinfo contains base-class pointers to other
                // typeinfos; those are not vtable RTTI slots.
                if (isInsideTypeinfo(addr)) continue;
                found.add(addr);
            }
        }
        return found;
    }

    private static long readWord(byte[] b, int i, boolean bigEndian) {
        int v = bigEndian
                ? ((b[i] & 0xff) << 24) | ((b[i + 1] & 0xff) << 16)
                    | ((b[i + 2] & 0xff) << 8) | (b[i + 3] & 0xff)
                : ((b[i + 3] & 0xff) << 24) | ((b[i + 2] & 0xff) << 16)
                    | ((b[i + 1] & 0xff) << 8) | (b[i] & 0xff);
        return Integer.toUnsignedLong(v);
    }

    private boolean isInsideTypeinfo(long addr) {
        for (Map.Entry<Long, Integer> e : typeinfoSizes.entrySet()) {
            long start = e.getKey();
            if (addr >= start && addr < start + e.getValue()) return true;
        }
        return false;
    }

    private boolean isFunctionPointer(Address addr, long value) {
        for (Reference ref : currentProgram.getReferenceManager().getReferencesFrom(addr)) {
            if (ref instanceof ExternalReference) return true;
        }
        return isExecutable(value) || isExecutable(value & ~1L);
    }

    private boolean isExecutable(long value) {
        try {
            Address target = currentProgram.getMinAddress()
                    .getAddressSpace().getAddress(value);
            MemoryBlock block = currentProgram.getMemory().getBlock(target);
            return block != null && block.isExecute();
        } catch (Exception e) {
            return false;
        }
    }

    private MemoryBlock findRodataBlock() {
        Memory memory = currentProgram.getMemory();
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.getName().equals(".rodata") || block.getName().equals("rodata")) {
                return block;
            }
        }
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.isInitialized() && block.isRead()
                    && !block.isWrite() && !block.isExecute()) {
                return block;
            }
        }
        return null;
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

        Function func = currentProgram.getFunctionManager().getFunctionAt(target);
        if (func != null) return func.getName(true);

        Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(target);
        return (sym != null) ? sym.getName(true) : "";
    }

    // ---------------------------------------------------------------
    //  Output
    // ---------------------------------------------------------------

    private void write(PrintWriter out) {
        List<String> names = new ArrayList<>(classes.keySet());
        Collections.sort(names);

        out.println("# Class hierarchy for " + currentProgram.getName());
        out.println("# Classes: " + names.size());
        out.println("# Sections: [CLASSES], [INHERITANCE], [VTABLES], [TREE]");
        out.println();

        out.println("[CLASSES]");
        out.println("# class_flags is __vmi_class_type_info::__flags (empty for non-vmi classes).");
        out.println("# vtables is the number of sub-vtables found; see [VTABLES].");
        out.println("# full_name\tnamespace\tsimple_name\trtti_kind\ttypeinfo\tmodule" +
                "\tclass_flags\tvtables");
        for (String name : names) {
            ClassInfo c = classes.get(name);
            out.printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d%n", c.fullName, c.namespaceName,
                    c.simpleName, c.rttiKind, c.typeinfoAddr, c.module, c.classFlags,
                    vtablesByClass.getOrDefault(name, Collections.emptyList()).size());
        }
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

        out.println("[VTABLES]");
        out.println("# One line per vtable slot. sub_index 0 is the primary vtable; 1+ are");
        out.println("# secondary vtables (multiple / virtual inheritance), in address order.");
        out.println("# address_point is the first function slot, i.e. what a this-pointer");
        out.println("# stores; the RTTI slot is 4 before it and offset_to_top 8 before it.");
        out.println("# entry is the raw word, thumb bit included; 0 means an external");
        out.println("# reference, whose target is given as name. Only the current program is");
        out.println("# scanned, so bases living in another CRO have no vtable rows here.");
        out.println("# class\tsub_index\taddress_point\toffset_to_top\tslot_index\tentry\tname");
        for (String name : names) {
            List<VTableInfo> vts = vtablesByClass.get(name);
            if (vts == null) continue;
            for (int v = 0; v < vts.size(); v++) {
                VTableInfo vt = vts.get(v);
                for (int i = 0; i < vt.slots.size(); i++) {
                    long value = vt.slots.get(i);
                    Address slotAddr = vt.addressPoint.add(4L * i);
                    out.printf("%s\t%d\t0x%08x\t%d\t%d\t0x%08x\t%s%n",
                            name, v, vt.addressPoint.getOffset(), vt.offsetToTop,
                            i, value, describeEntry(slotAddr, value));
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
