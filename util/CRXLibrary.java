package util;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 */
public final class CRXLibrary implements AutoCloseable {

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
    /** The Ghidra Program associated with this module */
    private final Program program;
    /** The Ghidra Program's DomainFile */
    private final DomainFile programFile;

    private CRXLibrary(final CRXBuilder b) {
        name = b.name;
        segments = b.segments;
        crxBytes = b.crxBytes;
        program = b.program;
        programFile = b.programFile;
    }

    static class CRXBuilder {
        /** Mirrors CRXLibrary */
        private String name;
        /** Mirrors CRXLibrary */
        private SegmentBlock[] segments;
        /** Mirrors CRXLibrary */
        private byte[] crxBytes;
        /** Mirrors CRXLibrary */
        private Program program;
        /** Mirrors CRXLibrary */
        private final DomainFile programFile;
        /** The Ghidra Task Monitor */
        private final TaskMonitor monitor;

        /**
         * Constructs a builder for a CRXLibrary
         *
         * @param programFile The Ghidra DomainFile associated with this module
         * @param monitor The Ghidra Task Monitor
         */
        CRXBuilder(final DomainFile programFile, final TaskMonitor monitor) {
            this.programFile = programFile;
            this.monitor = monitor;
        }

        CRXBuilder crsFile(final File crsFile) throws IOException {
            crxBytes = Util.readFileBytes(crsFile);
            return this;
        }

        CRXLibrary build() throws CancelledException, IOException,
                VersionException, MemoryAccessException {
            assert programFile != null;
            assert monitor != null;
            program = (Program) programFile
                    // consumer, okToUpgrade, okToRecover
                    .getDomainObject(this, true, false, monitor);

            if (crxBytes == null) {
                // Attempt to reconstruct bytes from program
                crxBytes = Util.readProgramBytes(program);
            }
            if (!hasCRO0Magic(this.crxBytes)) {
                throw new InvalidCrxException(
                        "Not a CRO0 file: Lacking CRO0 magic");
            }

            int moduleNameSize = Util.getInt(this.crxBytes,
                    MODULE_NAME_SIZE_OFFSET);
            int moduleNameOffset = Util.getInt(this.crxBytes,
                    MODULE_NAME_OFFSET_OFFSET);
            this.name = Util.readCString(this.crxBytes,
                    moduleNameOffset, moduleNameSize);
            this.segments = SegmentBlock.fromCrx(crxBytes, program);

            // Create crx, perform consumer hand-off
            CRXLibrary crx = new CRXLibrary(this);
            crx.program.addConsumer(crx);
            crx.program.release(this);
            return crx;
        }

        private static boolean hasCRO0Magic(final byte[] crxBytes) {
            if (crxBytes == null) {
                throw new NullPointerException();
            }
            return Arrays.equals(crxBytes, CRO0_MAGIC_OFFSET,
                    CRO0_MAGIC_OFFSET + CRO0_MAGIC.length,
                    CRO0_MAGIC, 0, CRO0_MAGIC.length);
        }
    }

    /** @return the name of the module */
    public String getName() {
        return name;
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
     * @param monitor The Ghidra TaskMonitor
     * @return A CRXLibrary for the given code.bin Program
     */
    public static CRXLibrary fromStatic(final DomainFile codeFile,
                                        final File crsFile,
                                        final TaskMonitor monitor)
            throws IOException, CancelledException,
            MemoryAccessException, VersionException {
        return new CRXBuilder(codeFile, monitor)
                .crsFile(crsFile)
                .build();
    }

    /**
     * Construct a CRXLibrary from a relocatable object (.cro)
     * @param croFile The .cro file imported in Ghidra
     * @param monitor The Ghidra TaskMonitor
     * @return A CRXLibrary for the given .cro
     */
    public static CRXLibrary fromRO(final DomainFile croFile,
                                    final TaskMonitor monitor)
            throws IOException, MemoryAccessException,
            CancelledException, VersionException {
        return new CRXBuilder(croFile, monitor)
                .build();
    }

    /**
     * Acts as a destructor for CRXLibrary
     */
    @Override
    public void close() throws Exception {
        if (program != null) {
            program.release(this);
        }
    }
}
