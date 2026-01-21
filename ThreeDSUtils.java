// Not a script - utility helper - AlgebraManiacABC

import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.script.GhidraState;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

public class ThreeDSUtils {
    static int getInt(byte[] arr, long off) {
        return ByteBuffer.wrap(arr, (int) off, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    static void labelNamedData(String name, SegmentOffset off, SegmentBlock[] segments, Program program) throws Exception {
        Address addr = off.getAddr(segments);
        if (addr != null) {
            SymbolTable symbolTable = program.getSymbolTable();
            symbolTable.createLabel(addr, name, SourceType.IMPORTED);
        }
    }

    static void labelNamedData(String name, Address addr, Program program) throws Exception {
        program.getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
    }

    // The program must be open
    static byte[] getAllBytes(Program program) throws MemoryAccessException {
        Memory memory = program.getMemory();
        int blockCount = memory.getAllFileBytes().size();
        MemoryBlock[] blocks = Arrays.stream(memory.getBlocks())
                .filter(MemoryBlock::isInitialized)
                .sorted(Comparator.naturalOrder())
                .limit(blockCount)
                .toArray(MemoryBlock[]::new);
        int maxByte = (int) Arrays.stream(blocks)
                .max(Comparator.naturalOrder())
                .get().getEnd().getOffset();
        int minByte = (int) Arrays.stream(blocks)
                .min(Comparator.naturalOrder())
                .get().getStart().getOffset();
        int byteCount = maxByte - minByte + 1;
        byte[] bytes = new byte[byteCount];
        int offset = 0;
        for (MemoryBlock block : blocks) {
            offset = (int) block.getStart().getOffset();
            block.getBytes(block.getStart(), bytes, offset, (int) block.getSize());
        }
        return bytes;
    }

    static SegmentBlock[] readSegments(byte[] crx, Program program) {
        int segTableOffset = ThreeDSUtils.getInt(crx, 0xC8);
        int segCount = ThreeDSUtils.getInt(crx, 0xCC);
        SegmentBlock[] segments = new SegmentBlock[segCount];
        for (int i=0; i<segCount; i++) {
            segments[i] = new SegmentBlock(crx, segTableOffset + 12 * i, program);
//            printf("New segment found: %s\n", segments[i]);
        }
        return segments;
    }

    static List<RelocationEntry> getRelocs(byte[] arr, long off) {
        List<RelocationEntry> relocs = new ArrayList<>();

        int i = 0;
        while (true) {
            SegmentOffset segOff = new SegmentOffset(arr, off + 0xCL * i);
            RelocationEntry.Type type = RelocationEntry.Type.typeOf(arr[(int) (off + 0x4 + (0xC * i))]);
            byte last = arr[(int)(off + 0x5 + (0xC * i))];
            relocs.add(new RelocationEntry(segOff, type));
            if (last != 0) break;
            i++;
        }

        return relocs;
    }

    static List<RelocationEntry> getAndApplyRelocs(
            byte[] arr, long off, CROLibrary croLibrary, Program srcProgram,
            SegmentOffset symbolOffset, SegmentBlock[] segments,
            ProgramManager pman, ReferenceManager rman, TaskMonitor monitor) throws Exception {

        // Open program in background during processing
        URL croPath = croLibrary.croFile.getLocalProjectURL(null);
        Program croProgram = pman.openCachedProgram(croPath, croLibrary);

        // This is the address of the symbol, which will be patched
        //  into the crs several times
        Address symbolAddress = symbolOffset.getAddr(croLibrary.segments);
        Symbol[] symbols = croProgram.getSymbolTable().getSymbols(symbolAddress);
        String symName = null;
        if (symbols.length == 0) {
            // No symbol at address. Can we disassemble?
            int tx_id = croProgram.startTransaction(String.format("Disassemble %s", croLibrary.name));
            ArmDisassembleCommand adc = new ArmDisassembleCommand(
                    symbolAddress,
                    null,
                    1 == (symbolAddress.getOffset() & 1));
            try {
                adc.applyTo(croProgram, monitor);
            } catch (Exception e) {
                croProgram.endTransaction(tx_id, false);
                throw e;
            }
            croProgram.endTransaction(tx_id, true);
            if (adc.getDisassembledAddressSet() == null) {
//                printf("No symbol at address %s in %s, and couldn't disassemble!\n",
//                        symbolAddress, croLibrary.name);
            } else {
                symbols = croProgram.getSymbolTable().getSymbols(symbolAddress);
            }
        }

        if (symbols.length > 1) {
//            printf("More than 1 symbol for address %s in %s! Picking first.\n",
//                    symbolAddress, croLibrary.name);
            symName = symbols[0].getName();
        } else if (symbols.length == 1) {
            symName = symbols[0].getName();
        }

        List<RelocationEntry> relocs = ThreeDSUtils.getRelocs(arr, off);
        for (RelocationEntry patchAddress : relocs) {
            if (patchAddress.type == RelocationEntry.Type.R_ARM_ABS32) {
                // This is the location which will be patched by the value from symbolAddress
                Address crsAddress = patchAddress.off.getAddr(segments);

                if (symName == null) symName =
                        String.format("%s_%s",croLibrary.name,symbolAddress);
                ThreeDSUtils.labelNamedData(symName, crsAddress, srcProgram);
//                printf("Creating reference to %s at %s\n", symbolAddress, crsAddress);
                // Link back into library
                rman.addExternalReference(
                        crsAddress,
                        croLibrary.library,
                        symName,
                        symbolAddress,
                        SourceType.IMPORTED,
                        0,
                        RefType.DATA);
            } else {
//                printf("\tFrom %s @ %s to %s (%s) - NOT YET IMPLEMENTED\n",
//                        croLibrary.name, symbolOffset, patchAddress.off, patchAddress.type);
            }
        }

        // Release program
        croProgram.release(croLibrary);

        return relocs;
    }


}

class SegmentBlock {
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

    Address getStart() { return segmentStart; }
    long getSize() { return segmentSize; }
    Address getEnd() { return segmentStart.add(segmentSize); }

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

class SegmentOffset {
    SegmentOffset.ID segmentIndex;
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
            this.segmentIndex = SegmentOffset.ID.INVALID;
            this.segmentOffset = 0;
        } else {
            this.segmentIndex = SegmentOffset.ID.values()[(int)(val & 0xf)];
            this.segmentOffset = (int)(val >> 4);
        }
    }

    SegmentOffset(byte[] arr, long off) {
        this(ThreeDSUtils.getInt(arr,off) & 0xFFFFFFFFL);
    }

    SegmentOffset.ID getIndex() { return segmentIndex; }
    int getOffset() { return segmentOffset; }

    public String toString() {
        if (segmentIndex == SegmentOffset.ID.INVALID) return "N/A";
        return String.format("%s:%08x",segmentIndex,segmentOffset);
    }

    Address getAddr(SegmentBlock[] segments) {
        for (SegmentBlock segment : segments) {
            if (segment.id != segmentIndex.ordinal()) continue;
            return segment.getStart().add(segmentOffset);
        }
        return null;
    }
}

class RelocationEntry {
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

class CROLibrary {
    Library library;
    DomainFile croFile;
    SegmentBlock[] segments;
    String name;

    CROLibrary(DomainFile croFile, Program program, ProgramManager pman) throws Exception {
        this.croFile = croFile;
        ExternalManager exman = program.getExternalManager();
        this.library = exman.addExternalLibraryName(croFile.getName(), SourceType.IMPORTED);
        exman.setExternalPath(this.library.getName(), croFile.getPathname(), true);

        Program croProgram = pman.openCachedProgram(croFile, this);
        byte[] croBytes = ThreeDSUtils.getAllBytes(croProgram);
        this.segments = ThreeDSUtils.readSegments(croBytes, croProgram);
        croProgram.release(this);

        this.name = croFile.getName();
    }
}