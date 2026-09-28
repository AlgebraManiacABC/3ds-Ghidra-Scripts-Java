package util;

/**
 * One inheritance edge, decoded from {@code __base_class_type_info::__offset_flags}
 * (Itanium C++ ABI 2.9.5.6.3).
 *
 * <p>A {@code __si_class_type_info} base carries no flags word of its own -- it is
 * always public, non-virtual and at offset 0 -- so callers synthesize
 * {@link #PUBLIC_MASK} for it and every edge reads the same way.
 *
 * <p>For a virtual base {@link #offset} is <em>not</em> a byte offset into the object;
 * it is the byte offset, <em>within the vtable</em>, of the word holding the virtual
 * base's real position, measured from the sub-table's address point and therefore
 * always negative. The position of the subobject itself depends on the most-derived
 * type and has to be read out of that word. Consumers must check {@link #isVirtual}
 * before treating {@link #offset} as a location, and use
 * {@link #vbaseOffsetIndex(int)} to turn it into an index.
 */
public record BaseRef(String name, int offsetFlags) {

    public static final int VIRTUAL_MASK = 0x1;
    public static final int PUBLIC_MASK = 0x2;
    public static final int OFFSET_SHIFT = 8;

    public boolean isVirtual() {
        return (offsetFlags & VIRTUAL_MASK) != 0;
    }

    public boolean isPublic() {
        return (offsetFlags & PUBLIC_MASK) != 0;
    }

    /**
     * Byte offset of the subobject, or -- when {@link #isVirtual} -- the location of the
     * vbase-offset word within the vtable, relative to the address point.
     */
    public int offset() {
        return offsetFlags >> OFFSET_SHIFT;   // arithmetic: offsets may be negative
    }

    /**
     * Index into a sub-table's {@code vbaseOffsets[]} for a virtual base, or -1 when
     * {@link #offset} does not name a word inside that run.
     *
     * <p>A sub-table is laid out {@code [vbase_offset_0 .. vbase_offset_n-1]
     * [offset_to_top] [typeinfo] [slot 0 ...]}, with the address point at slot 0, so the
     * head sits at {@code addressPoint - 4*(2 + vbaseCount)} and word <i>i</i> of the run
     * sits at {@code 4*i - 4*(2 + vbaseCount)} from the address point. Inverting that
     * gives the index below. The words are stored in memory order, so this indexes them
     * directly.
     *
     * @param vbaseCount the number of vbase-offset words on the class's primary sub-table
     */
    public int vbaseOffsetIndex(int vbaseCount) {
        if (!isVirtual()) return -1;
        int off = offset();
        if (off >= 0 || (off % 4) != 0) return -1;
        int index = off / 4 + 2 + vbaseCount;
        return (index >= 0 && index < vbaseCount) ? index : -1;
    }

    /** The base whose subobject starts the derived object, and so shares its vptr. */
    public boolean isPrimary() {
        return !isVirtual() && offset() == 0;
    }
}
