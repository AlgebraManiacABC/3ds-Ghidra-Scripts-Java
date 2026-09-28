// ApplyCROHeader.java
// Applies the 0x138-byte CRO0Header struct to every CRO0 module found in the
// current program. The struct the CRO importer leaves at the data type root is
// reused; an equivalent one is built only if the program does not have it.
//
// Nothing is linked or resolved here -- the script only lays the struct over the
// first 0x138 bytes of each module so the header fields are readable in the
// listing. The header proper starts 0x80 bytes before the "CRO0" magic, which is
// what the script searches for.
//
// See https://www.3dbrew.org/wiki/CRO0
//
// @category 3DS

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

import java.util.ArrayList;
import java.util.List;

public class ApplyCROHeader extends GhidraScript {

    /** Offset of the "CRO0" magic from the start of the header. */
    private static final int MAGIC_OFFSET = 0x80;
    private static final byte[] MAGIC = new byte[]{'C', 'R', 'O', '0'};
    private static final int HEADER_SIZE = 0x138;
    /** Name the CRO importer gives the header struct at the data type root. */
    private static final String HEADER_NAME = "CRO0Header";

    private DataTypeManager dtm;
    /** Length of the struct actually being applied; usually HEADER_SIZE. */
    private int headerLength = HEADER_SIZE;

    @Override
    protected void run() throws Exception {
        dtm = currentProgram.getDataTypeManager();
        DataType header = getOrCreateHeaderStruct();
        headerLength = header.getLength();

        List<Address> headers = findHeaders();
        if (headers.isEmpty()) {
            popup("No CRO0 magic found in this program.");
            return;
        }

        int applied = 0;
        for (Address addr : headers) {
            if (applyHeader(addr, header)) applied++;
        }
        println(String.format("Applied %s to %d of %d CRO0 module(s).",
                header.getName(), applied, headers.size()));
    }

    /**
     * Finds the start of every CRO0 header in the program, i.e. 0x80 bytes
     * before each "CRO0" magic that has room for a full header.
     */
    private List<Address> findHeaders() throws Exception {
        List<Address> headers = new ArrayList<>();
        Memory memory = currentProgram.getMemory();
        Address addr = currentProgram.getMinAddress();
        while (addr != null && !monitor.isCancelled()) {
            addr = memory.findBytes(addr, MAGIC, null, true, monitor);
            if (addr == null) break;
            // The magic can also show up inside string tables or relocation
            // data, so only accept it when a whole header fits in one block.
            Address start = null;
            try {
                start = addr.subtract(MAGIC_OFFSET);
                MemoryBlock block = memory.getBlock(start);
                if (block == null || !block.contains(start.add(headerLength - 1))) start = null;
            } catch (AddressOutOfBoundsException e) {
                start = null;
            }
            if (start != null) {
                headers.add(start);
            } else {
                printerr("Skipping CRO0 magic at " + addr +
                        ": no room for a full header before it.");
            }
            try {
                addr = addr.add(MAGIC.length);
            } catch (AddressOutOfBoundsException e) {
                break;
            }
        }
        return headers;
    }

    /**
     * Clears whatever is at the header and lays the struct down, labelling it
     * with the module name when one has not already been placed there.
     */
    private boolean applyHeader(Address addr, DataType header) {
        try {
            clearListing(addr, addr.add(headerLength - 1));
            Data data = createData(addr, header);
            if (getSymbolAt(addr) == null) {
                createLabel(addr, "CRO_Header_" + addr, true, SourceType.USER_DEFINED);
            }
            println("  OK:   header at " + addr);
            return data != null;
        } catch (Exception e) {
            printerr("  FAIL: header at " + addr + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Returns the CRO0Header struct the CRO importer leaves at the data type
     * root, falling back to building an equivalent one when the current program
     * was not produced by that importer.
     */
    private DataType getOrCreateHeaderStruct() {
        DataType existing = dtm.getDataType(CategoryPath.ROOT, HEADER_NAME);
        if (existing == null) {
            // Some importer versions file it under a category of their own.
            List<DataType> found = new ArrayList<>();
            dtm.findDataTypes(HEADER_NAME, found);
            if (!found.isEmpty()) existing = found.getFirst();
        }
        if (existing != null) {
            println(String.format("Reusing existing %s (0x%X bytes).",
                    existing.getPathName(), existing.getLength()));
            if (existing.getLength() != HEADER_SIZE) {
                printerr(String.format("  NOTE: expected a 0x%X byte header.", HEADER_SIZE));
            }
            return existing;
        }

        println("No " + HEADER_NAME + " found; creating one.");
        StructureDataType s = new StructureDataType(CategoryPath.ROOT, HEADER_NAME, 0);
        DataType sha256 = new ArrayDataType(ByteDataType.dataType, 0x20, 1);

        s.add(sha256, "hash_header", "SHA-256 over 0x80 .. code offset");
        s.add(sha256, "hash_code", "SHA-256 over code offset .. module name offset");
        s.add(sha256, "hash_module_name", "SHA-256 over module name offset .. data offset");
        s.add(sha256, "hash_data",
                "SHA-256 over data offset .. data offset + data size (RO does not check this)");
        s.add(new ArrayDataType(CharDataType.dataType, 4, 1), "magic", "\"CRO0\"");
        u32(s, "name_offset", null);
        u32(s, "next_cro", "Next loaded CRO pointer, set by RO during loading");
        u32(s, "prev_cro", "Previous loaded CRO pointer, set by RO during loading");
        u32(s, "file_size", null);
        u32(s, "bss_size", null);
        u32(s, "fixed_size", "Set by RO after fixing, to keep track of the new size");
        u32(s, "unknown_0x9C", null);
        u32(s, "nnroControlObject_offset",
                "Segment offset of export symbol \"nnroControlObject_\"; 0xFFFFFFFF in CRS");
        u32(s, "on_load_offset",
                "Segment offset of OnLoad, called when the module is initialized; " +
                        "0xFFFFFFFF if absent");
        u32(s, "on_exit_offset",
                "Segment offset of OnExit, called when the module is finalized; " +
                        "0xFFFFFFFF if absent");
        u32(s, "on_unresolved_offset",
                "Segment offset of OnUnresolved, called when an unresolved function is " +
                        "called; 0xFFFFFFFF if absent");
        u32(s, "code_offset", null);
        u32(s, "code_size", null);
        u32(s, "data_offset", null);
        u32(s, "data_size", null);
        u32(s, "module_name_offset", null);
        u32(s, "module_name_size", null);
        u32(s, "segment_table_offset", null);
        u32(s, "segment_table_num", "size = num * 12");
        u32(s, "named_export_table_offset", null);
        u32(s, "named_export_table_num", "size = num * 8");
        u32(s, "indexed_export_table_offset", null);
        u32(s, "indexed_export_table_num", "size = num * 4");
        u32(s, "export_strings_offset", null);
        u32(s, "export_strings_size", null);
        u32(s, "export_trie_offset", null);
        u32(s, "export_trie_num", "size = num * 8");
        u32(s, "import_module_table_offset", null);
        u32(s, "import_module_table_num", "size = num * 20");
        u32(s, "import_relocations_offset", null);
        u32(s, "import_relocations_num", "size = num * 12");
        u32(s, "named_import_table_offset", null);
        u32(s, "named_import_table_num", "size = num * 8");
        u32(s, "indexed_import_table_offset", null);
        u32(s, "indexed_import_table_num", "size = num * 8");
        u32(s, "anonymous_import_table_offset", null);
        u32(s, "anonymous_import_table_num", "size = num * 8");
        u32(s, "import_strings_offset", null);
        u32(s, "import_strings_size", null);
        u32(s, "unknown_relocations_base_offset", null);
        u32(s, "unknown_relocations_base_num", "size = num * 8");
        u32(s, "internal_relocations_offset", null);
        u32(s, "internal_relocations_num", "size = num * 12");
        u32(s, "unknown_relocations_offset", null);
        u32(s, "unknown_relocations_num", "size = num * 12");

        if (s.getLength() != HEADER_SIZE) {
            // A mismatch means the field list above drifted from the spec.
            throw new IllegalStateException(String.format(
                    "CRO_Header is 0x%X bytes, expected 0x%X", s.getLength(), HEADER_SIZE));
        }
        return dtm.resolve(s, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    private void u32(StructureDataType s, String name, String comment) {
        s.add(UnsignedIntegerDataType.dataType, 4, name, comment);
    }
}
