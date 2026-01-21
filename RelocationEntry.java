import java.util.HashMap;
import java.util.Map;

public class RelocationEntry {
    enum Type {
        R_ARM_NONE((byte) 0),
        R_ARM_ABS32((byte) 2),
        R_ARM_REL32((byte) 3),
        R_ARM_THM_PC22((byte) 10),
        R_ARM_CALL((byte) 28),
        R_ARM_JUMP24((byte) 29),
        R_ARM_TARGET1((byte) 38),
        R_ARM_PREL31((byte) 42);

        public final byte i;
        private static final Map<Byte, Type> BY_VALUE = new HashMap<>();

        static {
            for (Type t : values()) {
                BY_VALUE.put(t.i, t);
            }
        }
        Type(byte i) {
            this.i = i;
        }
        static Type typeOf(byte b) {
            Type type = BY_VALUE.get(b);
            if (type == null) {
                throw new IllegalArgumentException("Unknown relocation type: " + b);
            }
            return type;
        }
    }

    SegmentOffset off;
    Type type;

    RelocationEntry(SegmentOffset off, Type type) {
        this.off = off;
        this.type = type;
    }

    public String toString() {
        return String.format("%s: %s", type, off);
    }
}
