package util;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 */
public final class CRXLibrary {

    /** The file's magic identifier */
    private static final byte[] CRO0_MAGIC =
            "CRO0".getBytes(StandardCharsets.UTF_8);
    /** The file magic begins at 0x80, after the checksums */
    private static final int CRO0_MAGIC_OFFSET = 0x80;
    /** Where in the crx file the module's name exists */
    private static final int MODULE_NAME_OFFSET_OFFSET = 0xC0;
    /** Where in the crx file the module's name's size is stored */
    private static final int MODULE_NAME_SIZE_OFFSET = 0xC4;


    /** The name of the module, as used internally */
    private final String name;
    /** The segments inside the module */
    private final SegmentBlock[] segments;
    /** The raw bytes from the associated crx file
     * If this is code.bin, then this contains static.crs */
    private final byte[] crxBytes;

    private CRXLibrary(final CRXBuilder b) {
        name = b.name;
        segments = b.segments;
        crxBytes = b.crxBytes;
    }

    static class CRXBuilder {
        /** Mirrors CRXLibrary */
        private final String name;
        /** Mirrors CRXLibrary */
        private final SegmentBlock[] segments;
        /** Mirrors CRXLibrary */
        private final byte[] crxBytes;

        /**
         * Constructs a builder for a CRXLibrary
         *
         * @param crxBytes The real bytes of the original crx file
         * @param program  The Ghidra Program containing this library
         */
        CRXBuilder(final byte[] crxBytes,
                   final Program program) throws IOException {
            this.crxBytes = crxBytes;
            if (!hasCRO0Magic(this.crxBytes)) {
                throw new IOException("Not a CRO0 file: Lacking CRO0 magic");
            }
            int moduleNameSize = Util.getInt(this.crxBytes,
                    MODULE_NAME_SIZE_OFFSET);
            int moduleNameOffset = Util.getInt(this.crxBytes,
                    MODULE_NAME_OFFSET_OFFSET);
            this.name = Util.readCString(this.crxBytes,
                    moduleNameOffset, moduleNameSize);
            this.segments = SegmentBlock.fromCrx(crxBytes, program);
        }

        CRXLibrary build() {

            return new CRXLibrary(this);
        }

        private static boolean hasCRO0Magic(final byte[] crxBytes) {
            if (crxBytes == null) return false;
            return Arrays.equals(crxBytes, CRO0_MAGIC_OFFSET,
                    CRO0_MAGIC_OFFSET + CRO0_MAGIC.length,
                    CRO0_MAGIC, 0, CRO0_MAGIC.length);
        }
    }

    /** @return Succinct information about the module as a String */
    public String toString() {
        return String.format(
                "Module \"%s\"",
                name
        );
    }

    /**
     * Construct a CRXLibrary from the static binary (AKA .code, code.bin)
     *  using static.crs
     * @param codeFile The code.bin (static binary) file imported in Ghidra
     * @param crsFile The static.crs file (not imported)
     * @param program The Ghidra Program containing code.bin
     * @return A CRXLibrary for the given code.bin Program
     */
    public static CRXLibrary fromStatic(final DomainFile codeFile,
                                        final File crsFile,
                                        final Program program)
            throws IOException {
        CRXBuilder builder = new CRXBuilder(
                Util.readFileBytes(crsFile), program);
        return builder.build();
    }

    /**
     * Construct a CRXLibrary from a relocatable object (.cro)
     * @param croFile The .cro file imported in Ghidra
     * @param program The Ghidra Program containing said .cro
     * @return A CRXLibrary for the given .cro Program
     */
    static CRXLibrary fromRO(final DomainFile croFile, final Program program)
            throws IOException, MemoryAccessException {
        CRXBuilder builder = new CRXBuilder(
                Util.readProgramBytes(program), program);
        return builder.build();
    }
}
