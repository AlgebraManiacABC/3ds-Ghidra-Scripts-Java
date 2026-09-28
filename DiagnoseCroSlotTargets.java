// Which words in a CRO's memory hold the small addresses that unrelated classes' vtables
// seem to share, and where did those values come from?
//
// For each module/address pair below, scans the module's initialized memory for words equal
// to the address (either Thumb bit), and prints for each hit: the word in memory, the word
// in the imported file at the same place, every reference from it, and the symbols on it
// (a vtable label or class namespace says whose table it is). Read-only.
//
//@category 3DS

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class DiagnoseCroSlotTargets extends GhidraScript {

    private static final Map<String, long[]> TARGETS = new LinkedHashMap<>();
    static {
        TARGETS.put("ModuleMusFish.cro", new long[]{0x2e8L, 0x32cL});
        TARGETS.put("ModuleMusIns.cro", new long[]{0x2d8L, 0x31cL});
        TARGETS.put("ModuleOutdoor.cro", new long[]{0x240L, 0x25cL});
    }
    private static final int MAX_HITS = 12;

    @Override
    protected void run() throws Exception {
        for (Map.Entry<String, long[]> e : TARGETS.entrySet()) {
            DomainFile file = find(state.getProject().getProjectData().getRootFolder(),
                    e.getKey());
            if (file == null) {
                println(e.getKey() + ": not found in the project");
                continue;
            }
            Program p = (Program) file.getDomainObject(this, true, false, monitor);
            try {
                for (long t : e.getValue()) scan(p, t);
            } finally {
                p.release(this);
            }
        }
    }

    private DomainFile find(DomainFolder folder, String name) {
        DomainFile f = folder.getFile(name);
        if (f != null) return f;
        for (DomainFolder sub : folder.getFolders()) {
            f = find(sub, name);
            if (f != null) return f;
        }
        return null;
    }

    private void scan(Program p, long target) throws Exception {
        println(String.format("=== %s: words holding 0x%x or 0x%x", p.getName(), target,
                target | 1));
        Memory mem = p.getMemory();
        int hits = 0;
        for (MemoryBlock b : mem.getBlocks()) {
            if (!b.isInitialized()) continue;
            long start = (b.getStart().getOffset() + 3) & ~3L;
            for (long off = start; off + 4 <= b.getEnd().getOffset() + 1; off += 4) {
                Address a = b.getStart().getNewAddress(off);
                long w = Integer.toUnsignedLong(mem.getInt(a));
                if ((w & ~1L) != target) continue;
                if (++hits > MAX_HITS) continue;
                StringBuilder sb = new StringBuilder(String.format(
                        "  %s [%s] memory %08x file %s", a, b.getName(), w, fileWord(p, a)));
                for (Reference r : p.getReferenceManager().getReferencesFrom(a)) {
                    if (r instanceof ExternalReference x) {
                        sb.append(String.format("  EXT %s::%s @%s", x.getLibraryName(),
                                x.getLabel(), x.getExternalLocation().getAddress()));
                    } else {
                        sb.append("  ref ").append(r.getToAddress())
                                .append(" ").append(r.getReferenceType());
                    }
                }
                println(sb.toString());
                // The nearest label at or before the word says whose table it sits in.
                Symbol owner = null;
                for (long back = off; back >= off - 0x400 && owner == null; back -= 4) {
                    for (Symbol s : p.getSymbolTable().getSymbols(b.getStart().getNewAddress(back))) {
                        if (s.getSource() == ghidra.program.model.symbol.SourceType.DEFAULT) continue;
                        owner = s;
                        break;
                    }
                }
                if (owner != null) {
                    println(String.format("      nearest label: %s at %s (+0x%x)",
                            owner.getName(true), owner.getAddress(),
                            off - owner.getAddress().getOffset()));
                }
            }
        }
        if (hits > MAX_HITS) println("  ... " + (hits - MAX_HITS) + " more");
        println("  " + hits + " words in all");
        Address t = p.getAddressFactory().getDefaultAddressSpace().getAddress(target);
        println(String.format("  at the target: memory %08x file %s, instruction %s",
                Integer.toUnsignedLong(mem.getInt(t)), fileWord(p, t),
                p.getListing().getInstructionAt(t)));
    }

    private String fileWord(Program p, Address a) {
        MemoryBlock block = p.getMemory().getBlock(a);
        if (block == null) return "(no block)";
        for (MemoryBlockSourceInfo info : block.getSourceInfos()) {
            if (!info.contains(a)) continue;
            if (info.getFileBytes().isEmpty()) return "(no file bytes)";
            FileBytes fb = info.getFileBytes().get();
            long off = info.getFileBytesOffset(a);
            try {
                long v = 0;
                for (int i = 3; i >= 0; i--) v = (v << 8) | (fb.getOriginalByte(off + i) & 0xffL);
                return String.format("%08x", v);
            } catch (Exception e) {
                return "(unreadable)";
            }
        }
        return "(no source)";
    }
}
