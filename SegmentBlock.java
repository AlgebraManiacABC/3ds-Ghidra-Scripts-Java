import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class SegmentBlock {
    Address segmentStart;
    long segmentSize;
    int id;

    SegmentBlock(Address start, long size, int id) {
        this.segmentStart = start;
        this.segmentSize = size;
        this.id = id;
    }

    SegmentBlock(byte[] arr, int offset, Program program) {
        // read the segment table entry:
        segmentStart = program.getAddressFactory().getDefaultAddressSpace().getAddress((ThreeDSUtils.getInt(arr, offset)));
        segmentSize = ThreeDSUtils.getInt(arr, offset + 4);
        id = ThreeDSUtils.getInt(arr, offset + 8);
    }

    public Address getStart() { return segmentStart; }
    public long getSize() { return segmentSize; }
    public Address getEnd() { return segmentStart.add(segmentSize); }
    public int getID() { return id; }

    public String toString() {
        return String.format("%s: %s (%08x)", idAsString(), segmentStart, segmentSize);
    }

    public String idAsString() {
        return switch(id) {
            case 0 -> ".text";
            case 1 -> ".rodata";
            case 2 -> ".data";
            case 3 -> ".bss";
            default -> "unknown section";
        };
    }
}
