package util;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/**
 * A segment of a CTR binary corresponding to a Ghidra Program.
 */
public class SegmentBlock {

    /** Location in a CRO0 file which contains
     *   the offset of the segment table */
    static final int SEGMENT_TABLE_ADDR_OFFSET = 0xC8;
    /** Location in a CRO0 file which contains
     *   the count of segments in the segment table */
    static final int SEGMENT_TABLE_COUNT_OFFSET = 0xCC;
    /** The size of a segment table entry */
    static final int SEGMENT_TABLE_ENTRY_SIZE = 12;
    /** The names of all segment types.
     *  The possible types are:
     *  <li>.text (read-only, executable)</li>
     *  <li>.rodata (read-only data)</li>
     *  <li>.data (readable and writable data)</li>
     *  <li>.bss (data-like; space for uninitialized and
     *   zero-initialized global variables)</li>
     */
    static final String[] SEGMENT_NAMES = {".text", ".rodata", ".data", ".bss"};

    /** The start of this segment as a Ghidra Address */
    private final Address start;
    /** This segment's size */
    private final long size;
    /** This segment's type */
    private final int id;

    /**
     * Construct a SegmentBlock from known values
     * @param start The start of the segment in the AddressSpace
     *              of the respective program
     * @param size The size of the segment
     * @param id The segment's type: 0 for .text, 1 for .rodata,
     *           2 for .data, 3 for .bss
     */
    SegmentBlock(final Address start, final long size, final int id) {
        this.start = start;
        this.size  = size;
        this.id    = id;
    }

    /** @return The segment's first Address */
    Address getStart() {
        return start;
    }
    /** @return The segment's size */
    long getSize() {
        return size;
    }
    /** @return The segment's last Address */
    Address getEnd() {
        return start.add(size - 1);
    }
    /** @return The segment's ID */
    long getId() {
        return id;
    }

    /** @return The segment's type, as a string */
    String getIdString() {
        return id >= 0 && id < SEGMENT_NAMES.length
                ? SEGMENT_NAMES[id]
                : "unknown";
    }

    /**
     * Creates a SegmentBlock from the segment table entry at the given
     *  offset into the given byte array
     * @param arr The byte array to offset into
     * @param offset The offset into the byte array where the segment table lays
     * @param program The corresponding Ghidra Program whose Address Space
     *                contains the segment table to create
     * @return A Program-specific SegmentBlock derived from the given bytes
     */
    static SegmentBlock fromSegmentTableEntry(final byte[] arr,
                                              final int offset,
                                              final Program program) {
        return new SegmentBlock(
                program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(Util.getInt(arr, offset)),
                Util.getInt(arr, offset + Integer.BYTES),
                Util.getInt(arr, offset + 2 * Integer.BYTES)
        );
    }

    /**
     * Creates an array of SegmentBlocks by reading the crx bytes' data
     *  as if from a CRO0 file
     * @param crxBytes The bytes of a valid CRO0 file
     * @param program The corresponding Ghidra Program whose Address Space
     *                contains the segment tables to create
     * @return An array of Program-specific SegmentBlocks
     *  derived from the given bytes
     */
    static SegmentBlock[] fromCrx(final byte[] crxBytes,
                                  final Program program) {
        int segmentTableOffset =
                Util.getInt(crxBytes, SEGMENT_TABLE_ADDR_OFFSET);
        int segmentCount = Util.getInt(crxBytes, SEGMENT_TABLE_COUNT_OFFSET);
        SegmentBlock[] segments = new SegmentBlock[segmentCount];
        for (int i = 0; i < segmentCount; i++) {
            segments[i] = fromSegmentTableEntry(crxBytes,
                    segmentTableOffset + SEGMENT_TABLE_ENTRY_SIZE * i, program);
        }
        return segments;
    }
}
