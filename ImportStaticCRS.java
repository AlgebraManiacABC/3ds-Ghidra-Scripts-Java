//
//
//@category 3DS

import java.io.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.demangler.*;
import ghidra.framework.model.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import util.*;

public class ImportStaticCRS extends GhidraScript {

    String getName(byte[] arr, long off) {
        long end = off;
        for(; end < arr.length && arr[(int)end] != 0; end++);
        return new String(arr, (int)off, (int)(end - off), StandardCharsets.UTF_8);
    }

    List<CROLibrary> getCROLibraries(DomainFolder croDirectory) throws Exception {
        DomainFile[] found = Arrays.stream(croDirectory.getFiles())
                .filter(df -> df.getName().endsWith(".cro"))
                .toArray(DomainFile[]::new);
        if (found.length == 0) return null;

        List<CROLibrary> croList = new ArrayList<>();
        ProgramManager pman = getState().getTool().getService(ProgramManager.class);
        for (DomainFile df : found) {
            croList.add(new CROLibrary(df, currentProgram, pman));
        }
        return croList;
    }

    SegmentBlock[] importSectionInformation(byte[] crs) throws Exception {
        // Get Sections from Table
        SegmentBlock[] segments = ThreeDSUtils.readSegments(crs, currentProgram);

        Memory memory = currentProgram.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();
        // First just join all blocks in the range
        // TODO: Fix this
        long maxAddr = Arrays.stream(segments)
                .mapToLong(s -> s.getStart().getOffset())
                .max().orElse(0);
        printf("Max address: %d\n", maxAddr);
        for (int i = 0; i < blocks.length - 1; i++) {
            MemoryBlock nextBlock = null;
            for (int j = i + 1; j < blocks.length; j++) {
                if (blocks[j].getStart().subtract(1).compareTo(blocks[i].getEnd()) == 0) {
                    nextBlock = blocks[j];
                    break;
                }
            }
            currentProgram.getMemory().join(blocks[i], nextBlock);
        }
        if (memory.getBlocks().length > 1) {
            throw new Exception("Couldn't join all blocks!");
        }
        // Shift entire memory 0x100000 (proper start of .code) using AddressSpace
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        currentProgram.setImageBase(space.getAddress(0x100000), true);
        // NOTE: This does not move imports such as "Reset", which I believe are actually system calls
        //  outside the developer's memory range.

        // Now split based on segment data
        MemoryBlock curBlock;
        for (SegmentBlock seg : segments) {
            if (seg.getSize() <= 0) continue;
            curBlock = memory.getBlock(seg.getStart());
            if (curBlock == null) {
                // Create entire block
                memory.createBlock(memory.getBlocks()[0], seg.idAsString(), seg.getStart(), seg.getSize());
                continue;
            } else {
                // Split start
                if (curBlock.getStart().compareTo(seg.getStart()) != 0) {
                    Address toSplit = seg.getStart();
                    memory.split(curBlock, toSplit);
                    curBlock = memory.getBlock(seg.getStart());
                }
                // Split end
                if (curBlock.getEnd().add(1).compareTo(seg.getEnd()) != 0) {
                    if (!curBlock.contains(seg.getEnd())) {
                        // Need to make a new block, then join
                        MemoryBlock toJoin = memory.createBlock(curBlock, "temp", curBlock.getEnd().add(1), seg.getSize() - curBlock.getSize());
                        memory.join(curBlock, toJoin);
                    } else {
                        memory.split(curBlock, seg.getEnd());
                    }
                }
                // Start and end split successfully.
            }
            // Set RWX
            switch(SegmentOffset.ID.values()[seg.getID()]) {
                case SegmentOffset.ID.TEXT ->
                        curBlock.setPermissions(true, false, true);
                case SegmentOffset.ID.RODATA ->
                        curBlock.setPermissions(true, false, false);
                case SegmentOffset.ID.DATA, SegmentOffset.ID.BSS ->
                        curBlock.setPermissions(true, true, false);
                default ->
                        throw new Exception("FAILURE TO GET SEGMENT INDEX!!!");
            }
            // Rename
            curBlock.setName(seg.idAsString());
        }
        // Now, remove any gaps in between
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.getName().contains("split")) {
                memory.removeBlock(block, monitor);
            }
        }
        return segments;
    }

    void labelOnExitLoadUnresolved(byte[] arr, SegmentBlock[] segments) throws Exception {
        SegmentOffset onLoad = new SegmentOffset(arr, 0xA4);
        labelNamedFunction("OnLoad", onLoad, segments);
        SegmentOffset onExit = new SegmentOffset(arr, 0xA8);
        labelNamedFunction("OnExit", onExit, segments);
        SegmentOffset onUnresolved = new SegmentOffset(arr, 0xAC);
        labelNamedFunction("OnUnresolved", onUnresolved, segments);
    }

    void labelNamedFunction(String name, SegmentOffset off, SegmentBlock[] segments) throws Exception {
        Address realAddr = off.getAddr(segments);
        if (realAddr != null) {
            boolean thumb = (realAddr.getOffset() & 0x1) == 1;
            Address addr = toAddr(realAddr.getOffset() & ~0x1);
            Function temp = getFunctionAt(addr);
            if (temp == null && (temp = getFunctionAt(realAddr)) == null) {
                // Try to make function, but disassemble first (if necessary)
                if (getInstructionAt(addr) == null) {
                    ArmDisassembleCommand adc = new ArmDisassembleCommand(addr, null, thumb);
                    adc.applyTo(currentProgram, monitor);
                    if (adc.getDisassembledAddressSet() == null || adc.getDisassembledAddressSet().isEmpty()) {
                        String message = String.format("adc was empty/null at %s: %s",
                                addr, adc.getDisassembledAddressSet());
                        printf(message);
                        throw new Exception(message);
                    }
                }
                CreateFunctionCmd cfc = new CreateFunctionCmd(addr, false); // findEntryPoint: false
                cfc.applyTo(currentProgram, monitor);
                temp = cfc.getFunction();
            }

            if (temp != null) {
                temp.setName(name, SourceType.IMPORTED);
            } else {
                printf("%s: %s ==> Not created at: %s\n",name, off, addr);
            }
        } else {
            printf("%s: %s ==> NULL Address!\n", name, off);
        }
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            popup("This script requires that .code/code.bin be open in the tool");
            return;
        }
        if (!currentProgram.getName().contains("code")) {
            popup("This script requires that .code/code.bin be open in the tool");
            printf("%s\n",currentProgram.getName());
            return;
        }

        File crs_file = askFile("Import static.crs","Import");
        byte[] crs;
        try (FileInputStream stream = new FileInputStream(crs_file)) {
            crs = new byte[(int) crs_file.length()];
            stream.read(crs);
        }

        // Next up:
        // Verify CRO file structure
        byte[] magic = new byte[] {'C', 'R', 'O', '0'};
        if (!Arrays.equals(Arrays.copyOfRange(crs,0x80,0x84),magic)) {
            popup("The file type is not a valid CRO0 :(");
            return;
        }

        // First, load and create libraries from files
        DomainFolder croDirectory = askProjectFolder("Select CRO Directory");
        List<CROLibrary> croLibraries = getCROLibraries(croDirectory);
        if (croLibraries == null)
            throw new NullPointerException("No cro libraries were found!");
        println("-------------------------------------------------------------------------------");

        int codeOff = ThreeDSUtils.getInt(crs, 0xB0);
        int codeSize = ThreeDSUtils.getInt(crs, 0xB4);
        int dataOff = ThreeDSUtils.getInt(crs, 0xB8);
        int dataSize = ThreeDSUtils.getInt(crs, 0xBC);
        printf("Code section: %08x (%08x bytes)\nData section: %08x (%08x bytes)\n",
                codeOff, codeSize, dataOff, dataSize);

        // Split/join/rename blocks
        SegmentBlock[] segments = importSectionInformation(crs);

        // Label OnLoad, OnExit, OnUnresolved:
        labelOnExitLoadUnresolved(crs, segments);

        // Exports
        int namedExportTableOff = ThreeDSUtils.getInt(crs, 0xD0);
        int namedExportTableNum = ThreeDSUtils.getInt(crs, 0xD4);
        printf("Named Export Table (%d): %08x\n",namedExportTableNum,namedExportTableOff);
        int indexedExportTableOff = ThreeDSUtils.getInt(crs, 0xD8);
        int indexedExportTableNum = ThreeDSUtils.getInt(crs, 0xDC);
        printf("Indexed Export Table (%d): %08x\n",indexedExportTableNum,indexedExportTableOff);

        for(int i=0; i<namedExportTableNum; i++) {
            String name = getName(crs, ThreeDSUtils.getInt(crs,namedExportTableOff + 8L * i));
            SegmentOffset off = new SegmentOffset(crs, namedExportTableOff + (8L * i) + 4);
            switch (off.getIndex()) {
                case SegmentOffset.ID.TEXT ->
                        labelNamedFunction(name, off, segments);
                case SegmentOffset.ID.RODATA, SegmentOffset.ID.DATA ->
                        ThreeDSUtils.labelNamedData(name, off, segments, currentProgram);
                case SegmentOffset.ID.BSS ->
                        printf("Found named data %s in: %s\n", name, off);
                default ->
                        throw new Exception("Unknown index type " + off.getIndex());
            }
        }

        // Demangle names
        var options = new DemanglerOptions();
        options.setApplySignature(true);
        for (Symbol symbol : currentProgram.getSymbolTable().getAllSymbols(true)) {
            String name = symbol.getName();
            Address addr = symbol.getAddress();
            List<DemangledObject> demangledObjects = DemanglerUtil.demangle(currentProgram, name, addr);
            if (!demangledObjects.isEmpty()) {
                demangledObjects.getFirst().applyTo(currentProgram, addr, new DemanglerOptions(), monitor);
            }
        }

        // Imports
        int importModuleTableOff = ThreeDSUtils.getInt(crs, 0xF0);
        int importModuleTableNum = ThreeDSUtils.getInt(crs, 0xF4);
        int namedImportTableOff = ThreeDSUtils.getInt(crs, 0x100);
        int namedImportTableNum = ThreeDSUtils.getInt(crs, 0x104);
        printf("Named Import Table (%d): %08x\n",namedImportTableNum,namedImportTableOff);

        // Read modules from the table, adding relocations as we go
        for (int i=0; i<importModuleTableNum; i++) {
            long step_i = 0x14L * i;
            String croName = getName(crs, ThreeDSUtils.getInt(crs,importModuleTableOff + step_i));
            int indexedOff = ThreeDSUtils.getInt(crs, importModuleTableOff + 0x4 + step_i);
            int indexedNum = ThreeDSUtils.getInt(crs, importModuleTableOff + 0x8 + step_i);
            int anonOff = ThreeDSUtils.getInt(crs, importModuleTableOff + 0xC + step_i);
            int anonNum = ThreeDSUtils.getInt(crs, importModuleTableOff + 0x10 + step_i);
//            printf("Module '%s':\n", name);
            // Now, for each indexed and anonymous import, let's take a look:
            for (int j=0; j<indexedNum; j++) {
                int symbolIndex = ThreeDSUtils.getInt(crs, indexedOff + 0x8L * j);
                int relocsOff = ThreeDSUtils.getInt(crs, indexedOff + 0x4 + (0x8L * j));
                printf("\tIndex %d; Relocs @ %08x\n", symbolIndex, relocsOff);
                List<RelocationEntry> relocs = ThreeDSUtils.getRelocs(crs, relocsOff);
                for (RelocationEntry reloc : relocs) {
                    printf("\t\t%s\n", reloc);
                }
            }
            for (int j=0; j<anonNum; j++) {
                SegmentOffset symbolOffset = new SegmentOffset(crs, anonOff + 0x8L * j);
                int relocsOff = ThreeDSUtils.getInt(crs, anonOff + 0x4 + (0x8L * j));
                CROLibrary croLibrary = croLibraries.stream()
                        .filter(l -> l.getName().toLowerCase().equals(croName.toLowerCase() + ".cro"))
                        .findFirst().orElse(null);
                if (croLibrary == null) {
                    throw new NullPointerException(
                            String.format("Library %s (%s) was not found in the library list!\n",
                                    croName, croName + ".cro"));
                }
                // Get managers
                ProgramManager pman = getState().getTool().getService(ProgramManager.class);
                ReferenceManager rman = currentProgram.getReferenceManager();
                ThreeDSUtils.getAndApplyRelocs(crs, relocsOff, croLibrary, currentProgram, symbolOffset, segments, this, pman, rman, monitor);
            }
        }
//        printf("Imported %s relocation names!\n", relocation_sum);
    }
}