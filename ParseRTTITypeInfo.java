// Parse RTTI typeinfo structs from the current selection.
// Learns vtable pointer -> struct type mappings iteratively.
// @category RTTI
// @author Claude (for AlgebraManiacABC)

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.Memory;

import java.util.*;

public class ParseRTTITypeInfo extends GhidraScript {

    private static final int PTR_SIZE = 4;
    private static final String OPTIONS_KEY = "RTTI_VTABLE_MAP";
    private static final CategoryPath TYPE_INFO_PATH = new CategoryPath("/type_info");

    // Persistent across Ghidra session (not across restarts — program options used for that)
    private final Map<Long, String> vtableMap = new HashMap<>();

    private static final String[] RTTI_CHOICES = {
            "__class_type_info",
            "__si_class_type_info",
            "__vmi_class_type_info"
    };

    @Override
    protected void run() throws Exception {
        if (currentSelection == null || currentSelection.isEmpty()) {
            printerr("No selection. Select the region containing typeinfo struct(s).");
            return;
        }

        loadVtableMap();

        Address addr = currentSelection.getMinAddress();
        Address endAddr = currentSelection.getMaxAddress();

        while (addr != null && addr.compareTo(endAddr) <= 0) {
            Address next = parseOneTypeInfo(addr, endAddr);
            if (next == null) {
                break;
            }
            addr = next;
        }

        saveVtableMap();
    }

    private Address parseOneTypeInfo(Address addr, Address endAddr) throws Exception {
        Memory mem = currentProgram.getMemory();
        SymbolTable symTable = currentProgram.getSymbolTable();
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        // Read vtable pointer at offset 0
        long vtableAddr = Integer.toUnsignedLong(mem.getInt(addr));

        // If vtable pointer is zero or OnUnresolved, try to resolve
        // via external reference
        long resolvedVtableAddr = vtableAddr;
        if (vtableAddr == 0 || isOnUnresolved(vtableAddr)) {
            Long extAddr = resolveExternalReference(addr);
            if (extAddr != null) {
                resolvedVtableAddr = extAddr;
            } else {
                println("Couldn't resolve vtableAddr at " + addr);
            }
        }

        // Determine struct base type (class, si, or vmi)
        String baseType = vtableMap.get(resolvedVtableAddr);
        if (baseType == null) {
            baseType = askForStructType(addr, resolvedVtableAddr);
            if (baseType == null) {
                printerr("Cancelled at " + addr);
                return null;
            }
            vtableMap.put(resolvedVtableAddr, baseType);
        }

        // Resolve actual struct name — for __vmi, read base_count at offset 12
        String structName = baseType;
        if (baseType.equals("__vmi_class_type_info")) {
            int baseCount = mem.getInt(addr.add(12));
            structName = "__vmi_class_type_info_" + baseCount;
            println("  __vmi base_count = " + baseCount);
        }

        // Find the data type
        DataType dt = dtm.getDataType(TYPE_INFO_PATH, structName);
        if (dt == null) {
            printerr("Data type not found: " + TYPE_INFO_PATH + "/" + structName);
            printerr("Make sure the struct exists in the Data Type Manager.");
            return null;
        }

        int structSize = dt.getLength();

        // Check we have enough room in the selection
        Address structEnd = addr.add(structSize - 1);
        if (structEnd.compareTo(endAddr) > 0) {
            printerr("Not enough room for " + structName + " at " + addr +
                    " (need " + structSize + " bytes, selection ends at " + endAddr + ")");
            return null;
        }

        // Save external references first — applying the struct will clobber them
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Map<Address, List<Reference>> savedExtRefs = new HashMap<>();
        for (long offset = 0; offset < structSize; offset += PTR_SIZE) {
            Address fieldAddr = addr.add(offset);
            Reference[] refs = refMgr.getReferencesFrom(fieldAddr);
            for (Reference ref : refs) {
                if (ref instanceof ExternalReference) {
                    savedExtRefs.computeIfAbsent(fieldAddr, k -> new ArrayList<>())
                            .add(ref);
                }
            }
        }

        // Clear existing data at the location
        currentProgram.getListing().clearCodeUnits(addr, structEnd, false);

        // Apply the struct
        currentProgram.getListing().createData(addr, dt);
        println("Applied " + structName + " at " + addr);

        // Restore external references
        for (Map.Entry<Address, List<Reference>> entry : savedExtRefs.entrySet()) {
            Address fieldAddr = entry.getKey();
            for (Reference ref : entry.getValue()) {
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

        // Read the name pointer (offset 4) and derive the label
        long namePtr = Integer.toUnsignedLong(mem.getInt(addr.add(4)));
        Address namePtrAddr = addr.getNewAddress(namePtr);

        // Find existing symbol at the name pointer location
        Symbol[] nameSymbols = symTable.getSymbols(namePtrAddr);
        Namespace parentNs = null;

        for (Symbol sym : nameSymbols) {
            Namespace ns = sym.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                parentNs = ns;
                break;
            }
        }

        if (parentNs != null) {
            // Create or update "typeinfo" label under that namespace
            // First, check if there's already a symbol here we should rename
            Symbol[] existingSyms = symTable.getSymbols(addr);
            boolean found = false;
            for (Symbol sym : existingSyms) {
                if (sym.getParentNamespace().equals(parentNs) &&
                        sym.getName().equals("typeinfo")) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                createLabel(addr, "typeinfo", parentNs, true, SourceType.USER_DEFINED);
            }
            println("  -> " + parentNs.getName(true) + "::typeinfo");
        } else {
            println("  WARNING: No namespaced symbol found at name pointer " + namePtrAddr);
            println("  Could not determine class name for labeling.");
        }

        return addr.add(structSize);
    }

    private boolean isOnUnresolved(long addr) {
        Symbol sym = getSymbolAt(toAddr(addr));
        return sym.getName().equals("OnUnresolved");
    }

    private Long resolveExternalReference(Address addr) {
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Reference[] refs = refMgr.getReferencesFrom(addr);
        for (Reference ref : refs) {
            if (ref instanceof ExternalReference extRef) {
                return extRef.getExternalLocation().getAddress().getOffset();
            }
        }
        return null;
    }

    private String askForStructType(Address addr, long vtableAddr) throws Exception {
        String msg = String.format("""
                Unknown vtable pointer 0x%08x at %s
                
                Select the RTTI struct type:""", vtableAddr, addr);

        List<String> choices = new ArrayList<>(Arrays.asList(RTTI_CHOICES));

        return askChoice("Identify RTTI Type", msg,
                choices, choices.getFirst());
    }

    private void loadVtableMap() {
        vtableMap.clear();
        String stored = currentProgram.getOptions("RTTI_CHOICES")
                .getString(OPTIONS_KEY, "");
        if (stored.isEmpty()) {
            return;
        }
        // Format: "addr1=type1;addr2=type2;..."
        for (String entry : stored.split(";")) {
            String[] parts = entry.split("=", 2);
            if (parts.length == 2) {
                try {
                    vtableMap.put(Long.parseLong(parts[0], 16), parts[1]);
                } catch (NumberFormatException e) {
                    // skip
                }
            }
        }
        println("Loaded " + vtableMap.size() + " known vtable mappings.");
    }

    private void saveVtableMap() {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<Long, String> entry : vtableMap.entrySet()) {
            if (!sb.isEmpty()) sb.append(";");
            sb.append(Long.toHexString(entry.getKey()))
                    .append("=")
                    .append(entry.getValue());
        }
        currentProgram.getOptions("RTTI_CHOICES").setString(OPTIONS_KEY, sb.toString());
        println("Saved " + vtableMap.size() + " vtable mappings to program options.");
    }
}