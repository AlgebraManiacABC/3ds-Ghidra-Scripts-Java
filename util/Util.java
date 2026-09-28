package util;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Comparator;

/**
 * A small collection of general utility methods
 */
final class Util {
    private Util() {
        throw new UnsupportedOperationException(
                "Utility class cannot be instantiated");
    }

    /**
     * Retrieves a 4-byte integer in Little Endian format from the byte array
     * @param arr The byte array containing the integer
     * @param off The offset into the array at which the integer is located
     * @return The 4-byte LE integer found at the given offset into the array
     */
    static int getInt(final byte[] arr, final long off) {
        return ByteBuffer.wrap(arr, (int) off, Integer.BYTES)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    /**
     * Reads all bytes from the given file
     * @param file The file from which to read
     * @return A byte array containing all bytes from the file
     */
    static byte[] readFileBytes(final File file) throws IOException {
        byte[] bytes;
        try (FileInputStream stream = new FileInputStream(file)) {
            bytes = stream.readAllBytes();
        }
        return bytes;
    }

    /**
     * Reads all bytes from the given Ghidra Program.
     * The Program MUST be open.
     *
     * <p>Note: Discontiguous memory regions will leave
     *  zero-padding between regions.</p>
     *
     * @param program The Ghidra Program from which to read bytes
     * @return All bytes in all Memory Blocks of the Program,
     *  with zero-padding betwixt regions
     */
    static byte[] readProgramBytes(final Program program)
            throws MemoryAccessException {
        byte[] bytes;
        if (program == null || program.isClosed()) {
            throw new IllegalArgumentException(
                    "Provided program was not open!"
                    + " Please open the program before reading bytes.");
        }
        Memory memory = program.getMemory();
        MemoryBlock[] blocks = Arrays.stream(memory.getBlocks())
                .filter(MemoryBlock::isInitialized)
                .sorted(Comparator.naturalOrder())
                .toArray(MemoryBlock[]::new);
        long byteCount = blocks[blocks.length - 1].getEnd().getOffset()
                - blocks[0].getStart().getOffset() + 1;
        bytes = new byte[(int) byteCount];
        for (MemoryBlock block : blocks) {
            int offset = (int) block.getStart().getOffset();
            block.getBytes(block.getStart(), bytes,
                    offset, (int) block.getSize());
        }
        return bytes;
    }
}
