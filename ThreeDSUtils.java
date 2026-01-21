//@category 3DS
// Not a script - utility helper - AlgebraManiacABC

import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
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
    public static int getInt(byte[] arr, long off) {
        return ByteBuffer.wrap(arr, (int) off, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    public static void labelNamedData(String name, SegmentOffset off, SegmentBlock[] segments, Program program) throws Exception {
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

    public static SegmentBlock[] readSegments(byte[] crx, Program program) {
        int segTableOffset = ThreeDSUtils.getInt(crx, 0xC8);
        int segCount = ThreeDSUtils.getInt(crx, 0xCC);
        SegmentBlock[] segments = new SegmentBlock[segCount];
        for (int i=0; i<segCount; i++) {
            segments[i] = new SegmentBlock(crx, segTableOffset + 12 * i, program);
//            printf("New segment found: %s\n", segments[i]);
        }
        return segments;
    }

    public static List<RelocationEntry> getRelocs(byte[] arr, long off) {
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

    public static List<RelocationEntry> getAndApplyRelocs(
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
