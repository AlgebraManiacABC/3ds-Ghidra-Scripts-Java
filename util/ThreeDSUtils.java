// Not a script - utility helper - AlgebraManiacABC
package util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

public class ThreeDSUtils {
    public static int getInt(byte[] arr, long off) {
        return ByteBuffer.wrap(arr, (int) off, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    public static String getName(byte[] arr, long off) {
        long end = off;
        for(; end < arr.length && arr[(int)end] != 0; end++);
        return new String(arr, (int)off, (int)(end - off), StandardCharsets.UTF_8);
    }

    public static void labelNamedData(String name, SegmentOffset off, SegmentBlock[] segments, Program program) throws Exception {
        Address addr = off.getAddr(segments);
        if (addr != null) {
            SymbolTable symbolTable = program.getSymbolTable();
            symbolTable.createLabel(addr, name, SourceType.IMPORTED);
        }
    }

    public static Symbol labelNamedData(String name, Address addr, Program program) throws Exception {
        return program.getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
    }

    // The program must be open
    public static byte[] getAllBytes(Program program) throws MemoryAccessException {
        if (program == null) return null;
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

    public static byte[] getAllBytes(File file) throws IOException {
        byte[] bytes;
        try (FileInputStream stream = new FileInputStream(file)) {
            bytes = new byte[(int) file.length()];
            int read = stream.read(bytes);
            if (file.length() != read) throw new IOException("Byte count didn't match file size!");
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

    public static SegmentOffset toSegmentOffset(Address addr, SegmentBlock[] segments) {
        SegmentOffset segOff = null;
        for (int i = 0; i < segments.length; i++) {
            if (addr.compareTo(segments[i].getEnd()) > 0) continue;
            if (addr.compareTo(segments[i].getStart()) < 0) break;
            int id = segments[i].id;
            long val = (addr.getOffset() << 4) & id;
            segOff = new SegmentOffset(val);
        }
        return segOff;
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
            SegmentOffset symbolOffset, SegmentBlock[] segments, GhidraScript script,
            ProgramManager pman, ReferenceManager rman, TaskMonitor monitor) throws Exception {

        // Open program in background during processing
        URL croPath = croLibrary.croFile.getLocalProjectURL(null);
        Program croProgram = pman.openCachedProgram(croPath, script);

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
                script.printf("No symbol at address %s in %s, and couldn't disassemble!\n",
                        symbolAddress, croLibrary.getName());
                script.createBookmark(symbolAddress, BookmarkType.ANALYSIS, "Export symbol found here");
            }
        }

        List<RelocationEntry> relocs = ThreeDSUtils.getRelocs(arr, off);
        for (RelocationEntry patchAddress : relocs) {
            if (patchAddress.type == RelocationEntry.Type.R_ARM_ABS32) {
                // This is the location which will be patched by the value from symbolAddress
                Address crsAddress = patchAddress.off.getAddr(segments);

                if (symName == null) {
                    symName = String.format("%s_%s",croLibrary.getName(),symbolAddress);
                }
                ThreeDSUtils.labelNamedData(symName, crsAddress, srcProgram);
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
                script.printf("\tFrom %s @ %s to %s (%s) - NOT YET IMPLEMENTED\n",
                        croLibrary.name, symbolOffset, patchAddress.off, patchAddress.type);
            }
        }

        // Release program
        croProgram.release(script);

        return relocs;
    }

    // Guard against a runaway walk through mis-disassembled code.
    public static final long MAX_BODY_BYTES = 0x10000;

    /**
     * Derive a function's body by walking flow from its entry point: fall-through and
     * branch targets, but never into a call target or another function's entry point.
     * <p>
     * Functions created by CreateFunctionCmd before their bytes were disassembled keep
     * a 1-byte body forever, since later disassembly does not grow it. This recomputes
     * what the body should have been.
     */
    public static AddressSet deriveFunctionBody(Program program, Function func,
                                                TaskMonitor monitor) throws CancelledException {
        AddressSet body = new AddressSet();
        Address entry = func.getEntryPoint();
        Listing listing = program.getListing();
        FunctionManager fm = program.getFunctionManager();

        Deque<Address> work = new ArrayDeque<>();
        work.push(entry);

        while (!work.isEmpty()) {
            if (monitor != null) monitor.checkCancelled();
            Address addr = work.pop();
            if (body.contains(addr)) continue;
            if (body.getNumAddresses() > MAX_BODY_BYTES) break;

            // Do not absorb another function
            if (!addr.equals(entry) && fm.getFunctionAt(addr) != null) continue;

            Instruction instr = listing.getInstructionAt(addr);
            if (instr == null) continue;

            body.addRange(instr.getMinAddress(), instr.getMaxAddress());

            FlowType flow = instr.getFlowType();
            if (!flow.isCall()) {
                for (Address target : instr.getFlows()) {
                    if (target != null) work.push(target);
                }
            }
            if (!flow.isTerminal()) {
                Address next = instr.getFallThrough();
                if (next != null) work.push(next);
            }
        }
        return body;
    }
}
