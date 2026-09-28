// One-off migration from the first vtable struct layout to the current one.
//
// Legacy: RenameVTableFunctions applied a struct of nothing but function-pointer
// slots, named <Class>_vtable, at the vtable's *address point* (what a vptr
// stores), and put the class's "vtable" label there too.
//
// Current: the struct starts at the vtable *head* -- the offset-to-top word that
// _ZTV names, eight bytes earlier -- and reads
//     int              offset_to_top
//     <typeinfo> *     typeinfo
//     <Class>_vfuncs   funcs
// per sub-vtable, with contiguous sub-vtables sharing one struct. The function
// slots keep a struct of their own, <Class>_vfuncs, because that is what a vptr
// points at and so what a class struct's vtbl field must point to.
//
// This script rewrites the former into the latter in place: the legacy struct is
// *renamed* to <Class>_vfuncs, so every class struct's vtbl field follows along
// without being touched, and the "vtable" label moves back to the head.
//
// Re-running is safe -- structs already in the current layout are not legacy
// shaped and are passed over.
//
// @category RTTI
// @author Claude (for AlgebraManiacABC)

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import util.MangledNames;
import util.VtableScan;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ConvertLegacyVtables extends GhidraScript {

    private static final int PTR_SIZE = 4;
    private static final CategoryPath VTABLE_PATH = new CategoryPath("/vtables");

    // <flat class name>_vtable, or _vtable_<n> for a secondary sub-vtable.
    private static final Pattern LEGACY_NAME = Pattern.compile("^(.+?)_vtable(?:_(\\d+))?$");

    // An offset-to-top is 0 for a primary vtable and negative otherwise; nothing
    // near 16MB is plausible, so a word outside that range says the eight bytes
    // before the address point are not a vtable head.
    private static final long MAX_OFFSET_TO_TOP = 0x1000000L;

    /** One legacy sub-vtable: its slot struct and the address point it sits on. */
    private record Legacy(Address point, Structure struct) {}

    private DataTypeManager dtm;
    private SymbolTable symTab;
    private VtableScan scan;

    @Override
    protected void run() throws Exception {
        dtm = currentProgram.getDataTypeManager();
        symTab = currentProgram.getSymbolTable();
        scan = buildScan();

        Map<String, List<Legacy>> byClass = collectLegacyVtables();
        if (byClass.isEmpty()) {
            println("No legacy vtable structs found; nothing to convert.");
            return;
        }

        int subCount = 0;
        for (List<Legacy> subs : byClass.values()) subCount += subs.size();
        if (!askYesNo("Convert Legacy Vtables",
                "Found " + byClass.size() + " classes (" + subCount + " sub-vtables) in the " +
                "legacy layout.\n\nRename their slot structs to <Class>_vfuncs, rebuild " +
                "<Class>_vtable with offset-to-top and typeinfo, and move each \"vtable\" " +
                "label back to the head?")) {
            println("Cancelled; nothing changed.");
            return;
        }

        int converted = 0;
        int skipped = 0;
        int labelsMoved = 0;

        for (Map.Entry<String, List<Legacy>> entry : byClass.entrySet()) {
            if (monitor.isCancelled()) break;
            String flat = entry.getKey();
            List<Legacy> subs = entry.getValue();
            subs.sort(Comparator.comparing(Legacy::point));

            List<Address> heads = headsFor(flat, subs);
            if (heads == null) {
                skipped += subs.size();
                continue;
            }

            List<Structure> vfuncs = new ArrayList<>();
            for (int v = 0; v < subs.size(); v++) {
                vfuncs.add(renameToVfuncs(flat, v, subs.get(v).struct()));
            }

            // Sub-vtables sitting back to back are one object -- the object _ZTV names --
            // so they get one struct starting at the first offset-to-top.
            boolean contiguous = true;
            for (int v = 1; v < subs.size(); v++) {
                Address expected = subs.get(v - 1).point().add(subs.get(v - 1).struct().getLength());
                if (!expected.equals(heads.get(v))) {
                    contiguous = false;
                    break;
                }
            }

            if (contiguous) {
                StructureDataType s = new StructureDataType(VTABLE_PATH, flat + "_vtable", 0, dtm);
                for (int v = 0; v < subs.size(); v++) {
                    addSubVtableFields(s, heads.get(v), vfuncs.get(v), v);
                }
                Structure resolved = (Structure) dtm.resolve(s, DataTypeConflictHandler.REPLACE_HANDLER);
                if (applyVtableStruct(heads.getFirst(), resolved)) {
                    converted += subs.size();
                } else {
                    skipped += subs.size();
                }
            } else {
                println("    WARNING: " + flat +
                        " has non-contiguous sub-vtables; typing each one separately");
                for (int v = 0; v < subs.size(); v++) {
                    String structName = (v == 0) ? flat + "_vtable" : flat + "_vtable_" + v;
                    StructureDataType s = new StructureDataType(VTABLE_PATH, structName, 0, dtm);
                    addSubVtableFields(s, heads.get(v), vfuncs.get(v), 0);
                    Structure resolved = (Structure) dtm.resolve(s, DataTypeConflictHandler.REPLACE_HANDLER);
                    if (applyVtableStruct(heads.get(v), resolved)) {
                        converted++;
                    } else {
                        skipped++;
                    }
                }
            }

            for (int v = 0; v < subs.size(); v++) {
                if (moveVtableLabel(subs.get(v).point(), heads.get(v))) labelsMoved++;
            }
        }

        printf("Done: %d sub-vtables converted, %d skipped, %d vtable labels moved to the head.\n",
                converted, skipped, labelsMoved);
    }

    // ---------------------------------------------------------------
    //  Discovery
    // ---------------------------------------------------------------

    /**
     * Every applied /vtables struct still in the legacy shape, grouped by the flat
     * class name its type is named for.
     */
    private Map<String, List<Legacy>> collectLegacyVtables() {
        Map<String, List<Legacy>> byClass = new LinkedHashMap<>();
        DataIterator iter = currentProgram.getListing().getDefinedData(true);
        while (iter.hasNext()) {
            if (monitor.isCancelled()) break;
            Data data = iter.next();
            if (!(data.getDataType() instanceof Structure s)) continue;
            if (!VTABLE_PATH.equals(s.getCategoryPath())) continue;
            if (!isLegacyShape(s)) continue;

            Matcher m = LEGACY_NAME.matcher(s.getName());
            if (!m.matches()) continue;

            byClass.computeIfAbsent(m.group(1), k -> new ArrayList<>())
                    .add(new Legacy(data.getAddress(), s));
        }
        return byClass;
    }

    /**
     * A legacy vtable struct is function-pointer slots and nothing else. The current
     * layout leads with the offset-to-top word, so it never matches.
     */
    private boolean isLegacyShape(Structure s) {
        if (s.getNumComponents() == 0) return false;
        for (int i = 0; i < s.getNumComponents(); i++) {
            String name = s.getComponent(i).getFieldName();
            if (name != null && name.startsWith("offset_to_top")) return false;
            if (!(s.getComponent(i).getDataType() instanceof Pointer)) return false;
        }
        return true;
    }

    /**
     * The head of each sub-vtable: the offset-to-top word two pointers before the
     * address point. Returns null -- and says why -- if any of them fails to read
     * like a head, since a half-converted class is worse than an unconverted one.
     */
    /**
     * Scan the program so a head can be found past any virtual-base offset words. Best
     * effort: with no typeinfo symbols there is nothing to scan, and every head then
     * falls back to the two-word form.
     */
    private VtableScan buildScan() {
        Map<Long, String> byAddr = new HashMap<>();
        for (Symbol sym : symTab.getAllSymbols(false)) {
            if (!sym.getName().equals("typeinfo")) continue;
            Namespace ns = sym.getParentNamespace();
            if (ns == null || ns.isGlobal()) continue;
            String className = ns.getName(true);
            if (className.startsWith("__cxxabiv1")) continue;
            byAddr.putIfAbsent(sym.getAddress().getOffset(), className);
        }
        if (byAddr.isEmpty()) {
            println("    NOTE: no typeinfo symbols, so virtual-base heads cannot be " +
                    "located; classes with virtual bases will be skipped rather than " +
                    "converted at the wrong head");
            return null;
        }
        Map<Long, Integer> sizes = new HashMap<>();
        for (Long addr : byAddr.keySet()) {
            Data d = getDataAt(toAddr(addr));
            sizes.put(addr, (d != null) ? d.getLength() : 8);
        }
        try {
            VtableScan s = new VtableScan(currentProgram, byAddr, sizes, Map.of(),
                    this::println, monitor);
            s.scan();
            return s;
        } catch (Exception e) {
            println("    WARNING: vtable scan failed (" + e.getMessage() + "); heads will " +
                    "assume no virtual bases");
            return null;
        }
    }

    /**
     * How many virtual-base offset words sit in front of the sub-table at this address
     * point, or 0 when the scan has nothing to say about it.
     */
    private int vbaseCountAt(Address point) {
        if (scan == null) return 0;
        VtableScan.SubTable sub = scan.subTableAtPoint(point);
        return (sub == null) ? 0 : sub.vbaseCount();
    }

    private List<Address> headsFor(String flat, List<Legacy> subs) {
        List<Address> heads = new ArrayList<>();
        for (Legacy sub : subs) {
            Address head;
            try {
                // offset-to-top and the RTTI slot, plus one word per virtual base in
                // front of them. Without the scan this falls back to the two-word form,
                // and the offset-to-top check below then correctly refuses a virtual-base
                // class rather than converting it at the wrong head.
                head = sub.point().subtract((long) PTR_SIZE * (2 + vbaseCountAt(sub.point())));
            } catch (Exception e) {
                println("    WARNING: skipping " + flat + "; no room for a head before " +
                        sub.point());
                return null;
            }
            if (!currentProgram.getMemory().contains(head)) {
                println("    WARNING: skipping " + flat + "; head " + head + " is not in memory");
                return null;
            }
            try {
                long offsetToTop = currentProgram.getMemory().getInt(head);
                long typeinfo = Integer.toUnsignedLong(
                        currentProgram.getMemory().getInt(head.add(PTR_SIZE)));
                if (offsetToTop > 0 || offsetToTop < -MAX_OFFSET_TO_TOP) {
                    println("    WARNING: skipping " + flat + "; " + head +
                            " does not read as an offset-to-top (" + offsetToTop + ")");
                    return null;
                }
                if (typeinfo == 0) {
                    println("    WARNING: skipping " + flat + "; null typeinfo pointer at " +
                            head.add(PTR_SIZE));
                    return null;
                }
            } catch (Exception e) {
                println("    WARNING: skipping " + flat + "; could not read the head at " + head);
                return null;
            }
            heads.add(head);
        }
        return heads;
    }

    // ---------------------------------------------------------------
    //  Conversion
    // ---------------------------------------------------------------

    /**
     * Rename the legacy struct in place. Renaming rather than rebuilding is the whole
     * trick: pointers to it -- every class struct's vtbl field -- keep pointing at the
     * same type, which is exactly the function-slots struct they were always meant to
     * name, and the data already applied at the address point stays applied.
     */
    private Structure renameToVfuncs(String flat, int v, Structure legacy) throws Exception {
        String name = (v == 0) ? flat + "_vfuncs" : flat + "_vfuncs_" + v;
        if (legacy.getName().equals(name)) return legacy;

        DataType clash = dtm.getDataType(VTABLE_PATH, name);
        if (clash != null && clash != legacy) {
            // A leftover from a half-finished run; the legacy struct is the live one.
            dtm.remove(clash);
        }
        legacy.setName(name);
        return legacy;
    }

    /**
     * Append one sub-vtable -- offset-to-top, RTTI pointer, then the function slots --
     * to a vtable struct. {@code suffixIdx} distinguishes the fields of sub-vtables
     * sharing one struct; pass 0 when the sub-vtable gets a struct of its own.
     */
    private void addSubVtableFields(StructureDataType s, Address head, Structure vfuncs,
                                    int suffixIdx) {
        String suffix = (suffixIdx == 0) ? "" : "_" + suffixIdx;
        s.add(IntegerDataType.dataType, PTR_SIZE, "offset_to_top" + suffix, "offset-to-top");
        s.add(typeinfoPtrFor(head.add(PTR_SIZE)), PTR_SIZE, "typeinfo" + suffix, "RTTI pointer");
        s.add(vfuncs, "funcs" + suffix, "virtual function slots");
    }

    /**
     * Pointer to the typeinfo struct this RTTI slot names, when one has already been
     * applied there; a plain pointer otherwise.
     */
    private DataType typeinfoPtrFor(Address rttiSlot) {
        try {
            long tiAddr = Integer.toUnsignedLong(currentProgram.getMemory().getInt(rttiSlot));
            Address ti = currentProgram.getMinAddress().getAddressSpace().getAddress(tiAddr);
            Data d = currentProgram.getListing().getDataAt(ti);
            if (d != null && d.getDataType() instanceof Structure ts) {
                return new PointerDataType(ts, PTR_SIZE);
            }
        } catch (Exception e) { /* fall through to a generic pointer */ }
        return PointerDataType.dataType;
    }

    /** Lay the new struct over the head, keeping the external refs clearing would drop. */
    private boolean applyVtableStruct(Address point, Structure vt) {
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Map<Address, List<Reference>> saved = new HashMap<>();
        for (int j = 0; j * PTR_SIZE < vt.getLength(); j++) {
            Address a = point.add((long) j * PTR_SIZE);
            for (Reference ref : refMgr.getReferencesFrom(a)) {
                if (ref instanceof ExternalReference) {
                    saved.computeIfAbsent(a, k -> new ArrayList<>()).add(ref);
                }
            }
        }
        try {
            currentProgram.getListing().clearCodeUnits(point, point.add(vt.getLength() - 1L), true);
            currentProgram.getListing().createData(point, vt);
        } catch (Exception e) {
            println("    WARNING: could not apply " + vt.getName() + " at " + point);
            return false;
        }
        for (var e : saved.entrySet()) {
            for (Reference ref : e.getValue()) {
                if (ref instanceof ExternalReference ext) {
                    try {
                        refMgr.addExternalReference(e.getKey(), ext.getLibraryName(), ext.getLabel(),
                                ext.getExternalLocation().getAddress(), ext.getSource(),
                                ref.getOperandIndex(), ref.getReferenceType());
                    } catch (Exception ignored) { /* the import is already back */ }
                }
            }
        }
        return true;
    }

    /**
     * Move a "vtable" label off the address point and onto the head, where _ZTV
     * points. Labels in the global namespace are left where they are: those are the
     * flat "X_vtable" address-point labels, which name the address point on purpose.
     */
    private boolean moveVtableLabel(Address point, Address head) {
        boolean moved = false;
        for (Symbol sym : symTab.getSymbols(point)) {
            if (!sym.getName().equals("vtable")) continue;
            Namespace ns = sym.getParentNamespace();
            if (ns == null || ns.isGlobal()) continue;
            try {
                symTab.createLabel(head, "vtable", ns, sym.getSource());
                sym.delete();
                moved = true;
                // The head is where _ZTV points, so its mangled spelling goes here too
                String enc = MangledNames.typeNameForClass(currentProgram, ns);
                if (enc != null) {
                    MangledNames.addMangled(this, currentProgram, head, "_ZTV" + enc);
                }
            } catch (Exception e) {
                println("    WARNING: could not move the vtable label for " +
                        ns.getName(true) + " from " + point + " to " + head);
            }
        }
        return moved;
    }
}
