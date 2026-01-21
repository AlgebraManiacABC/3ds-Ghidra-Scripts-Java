import ghidra.program.model.address.Address;

public class SegmentOffset {
    ID segmentIndex;
    int segmentOffset;

    public enum ID {
        TEXT,
        RODATA,
        DATA,
        BSS,
        INVALID
    }

    SegmentOffset(long val) {
        if (val == 0xFFFFFFFFL) {
            this.segmentIndex = ID.INVALID;
            this.segmentOffset = 0;
        } else {
            this.segmentIndex = ID.values()[(int)(val & 0xf)];
            this.segmentOffset = (int)(val >> 4);
        }
    }

    public SegmentOffset(byte[] arr, long off) {
        this(ThreeDSUtils.getInt(arr,off) & 0xFFFFFFFFL);
    }

    public ID getIndex() { return segmentIndex; }
    int getOffset() { return segmentOffset; }

    public String toString() {
        if (segmentIndex == ID.INVALID) return "N/A";
        return String.format("%s:%08x",segmentIndex,segmentOffset);
    }

    public Address getAddr(SegmentBlock[] segments) {
        for (SegmentBlock segment : segments) {
            if (segment.id != segmentIndex.ordinal()) continue;
            return segment.getStart().add(segmentOffset);
        }
        return null;
    }
}
