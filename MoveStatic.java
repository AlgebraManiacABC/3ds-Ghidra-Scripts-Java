//@category 3DS

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockException;
import util.SegmentBlock;
import util.SegmentOffset;
import util.ThreeDSUtils;

import java.io.File;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Set;

public class MoveStatic extends GhidraScript {
    @Override
    protected void run() throws Exception {
        File crsFile = askFile("Import static.crs", "OK");
        byte[] crs = ThreeDSUtils.getAllBytes(crsFile);

        byte[] magic = new byte[] {'C', 'R', 'O', '0'};
        if (!Arrays.equals(Arrays.copyOfRange(crs,0x80,0x84),magic)) {
            popup("The file type is not a valid CRO0 :(");
            return;
        }

        SegmentBlock[] segments = ThreeDSUtils.readSegments(crs, currentProgram);
        Memory memory = currentProgram.getMemory();
        MemoryBlock[] blocks = memory.getBlocks();
        // Double check all segments are proper already
        Set<SegmentBlock> segmentsToFind = new HashSet<>(Arrays.asList(segments));
        for (MemoryBlock block : blocks) {
            // Does this block correspond to a segment?
            SegmentBlock[] segs = segmentsToFind.stream().filter(s ->
                    (s.getStart() == block.getStart()) &&
                    (s.getEnd() == block.getEnd()))
                    .toArray(SegmentBlock[]::new);
            if (segs.length >= 1) {
                segmentsToFind.remove(segs[0]);
            } else {
                // Missing at least one block
                break;
            }
        }

        // If all segments found, we're good - don't change anything
        if (segmentsToFind.isEmpty()) return;

        // If not all segments found, we need to join/split/etc.
        // Join all blocks
        for (int i = 0; i < blocks.length - 1; i++) {
            int I = i;
            MemoryBlock nextBlock = Arrays.stream(blocks)
                    .filter(b -> b.getStart().compareTo(blocks[I].getStart()) > 0)
                    .min(Comparator.naturalOrder()).get();
            try {
                // If adjacent, join the two
                memory.join(blocks[I], nextBlock);
            } catch (MemoryBlockException e) {
                // If no adjacent block, make a new block in between and join the three
                long size = nextBlock.getStart().subtract(blocks[I].getEnd().add(1));
                byte[] zeros = new byte[(int) size];
                MemoryBlock temp = createMemoryBlock(
                        "temp", blocks[I].getEnd().add(1), zeros, false);
                memory.join(temp, nextBlock);
                memory.join(blocks[I], temp);
            }
        }

        currentProgram.setImageBase(toAddr(0x100000), true);

        // Split according to segment info
        for (SegmentBlock seg : Arrays.stream(segments)
                .sorted(Comparator.comparing(SegmentBlock::getStart))
                .toArray(SegmentBlock[]::new)) {
            if (seg.getSize() <= 0) continue;
            MemoryBlock curBlock = memory.getBlock(seg.getStart());
            if (curBlock == null) {
                // Must create block
                memory.createBlock(memory.getBlocks()[0],
                        seg.idAsString(), seg.getStart(), seg.getSize());
                continue;
            } else {
                // Split start if necessary
                if (curBlock.getStart().compareTo(seg.getStart()) < 0) {
                    memory.split(curBlock, seg.getStart());
                    curBlock = memory.getBlock(seg.getStart());
                }
                // Split end if necessary
                if (curBlock.getEnd().add(1).compareTo(seg.getEnd()) > 0) {
                    if (!curBlock.contains(seg.getEnd())) {
                        // Need to make a new block, then join
                        MemoryBlock temp = memory.createBlock(
                                curBlock,
                                "temp",
                                curBlock.getEnd().add(1),
                                seg.getSize() - curBlock.getSize());
                        memory.join(curBlock, temp);
                    } else {
                        memory.split(curBlock, seg.getEnd());
                    }
                }
            }
            // Set Read-Write-Execute
            switch (SegmentOffset.ID.values()[seg.getID()]) {
                case TEXT -> curBlock.setPermissions(true, false, true);
                case RODATA -> curBlock.setPermissions(true, false, false);
                case DATA, BSS -> curBlock.setPermissions(true, true, true);
                case INVALID -> throw new Exception("Unknown segment type!");
            }
            curBlock.setName(seg.idAsString());
        }

        // Remove any gaps in between
        for (MemoryBlock block : memory.getBlocks()) {
            if (block.getName().contains("split")) {
                memory.removeBlock(block, monitor);
            }
        }
    }
}
