package util;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 */
public class CRXLibrary {

    final String name;
    final SegmentBlock[] segments;
    byte[] crxBytes;

    static byte[] CRO0_MAGIC = "CRO0".getBytes(StandardCharsets.UTF_8);
    static boolean isValidCRO0(byte[] crxBytes) {
        if (crxBytes == null) return false;
        return Arrays.equals(crxBytes, 0x80, 0x84,
                CRO0_MAGIC, 0, CRO0_MAGIC.length);
    }

    private CRXLibrary(CRXBuilder b) {
        name = b.name;
        segments = b.segments;
        crxBytes = b.crxBytes;
    }

    static class CRXBuilder {
        private final String name;
        private final SegmentBlock[] segments;
        private final byte[] crxBytes;

        /**
         * Constructs a builder for a CRXLibrary
         * @param name The name of the library
         * @param crxBytes The real bytes of the original crx file
         * @param program The Ghidra Program containing this library
         */
        CRXBuilder(String name, byte[] crxBytes, Program program) throws IOException {
            this.name = name;
            this.crxBytes = crxBytes;
            this.segments = SegmentBlock.fromCrx(crxBytes, program);
        }

        CRXLibrary build() {
            return new CRXLibrary(this);
        }
    }

    /**
     * Construct a CRXLibrary from the static binary (AKA .code, code.bin)
     *  using static.crs
     * @param codeFile The code.bin (static binary) file imported in Ghidra
     * @param crsFile The static.crs file (not imported)
     * @param program The Ghidra Program containing code.bin
     * @return A CRXLibrary for the given code.bin Program
     */
    static CRXLibrary fromStatic(DomainFile codeFile, File crsFile, Program program) throws IOException {
        CRXBuilder builder = new CRXBuilder("|static|", Util.readFileBytes(crsFile), program);
        return builder.build();
    }

    static CRXLibrary fromRO(DomainFile croFile, Program program) throws IOException {
        CRXBuilder builder = new CRXBuilder(croFile.getName().split("\\.cro")[0], program);
        return builder.build();
    }
}
