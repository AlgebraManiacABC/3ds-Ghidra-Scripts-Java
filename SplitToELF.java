//@category 3DS

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import util.ThreeDSUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class SplitToELF extends GhidraScript {
    @Override
    protected void run() throws Exception {
        File compiled_bindir = askDirectory("Where are the compiled objects?","OK");
        if (compiled_bindir == null) return;
        File split_dir = askDirectory("Where to place split object files?","OK");
        if (split_dir == null) return;

        // First, find Addresses with compiled objects
        List<AddressPair> matches = new ArrayList<>();
        List<String> undefined = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(compiled_bindir.toPath())) {
            for (Path path : stream) {
                byte[] bin_bytes = null;
                byte[] mask = null;
                try (RandomAccessFile in = new RandomAccessFile(path.toFile(), "rw")) {
                    List<Integer> undefined_name_offsets = new ArrayList<>();
                    List<SymbolTableEntry> symtabEntries = new ArrayList<>();
                    List<byte[]> textData = new ArrayList<>();
                    List<Integer> textNameOffsets = new ArrayList<>();
                    List<Integer> relIndices = new ArrayList<>();
                    int strtab_idx = 0;
                    var eh = new ELFHeader(in);
                    List<SectionHeaderEntry> sectionHeaders = new ArrayList<>();
                    for (short i=0; i<eh.shnum; i++) {
                        // Seek to section header
                        in.seek(eh.shoff + eh.shentsize * i);
                        var sh = new SectionHeaderEntry(in);
                        sectionHeaders.add(sh);
                        switch (sh.type) {
                            case 1 -> {
                                // .text, .data, .rodata, etc.
                                in.seek(sh.off);
                                byte[] ba = new byte[sh.size];
                                in.readFully(ba, 0, sh.size);
                                textData.add(ba);
                                textNameOffsets.add(sh.name_off);
                            }
                            case 2 -> {
                                // .symtab
                                strtab_idx = sh.link;
                                in.seek(sh.off);
                                int numsym = sh.size / 0x10;
                                for(int j=0; j<numsym; j++) {
                                    var sym = new SymbolTableEntry(in);
                                    symtabEntries.add(sym);
//                                    if (sym.shndx == 0) {
//                                        // Undefined; must import
//                                        undefined_name_offsets.add(sym.name_off);
//                                    }
                                }
                            }
                            case 9 -> {
                                // .rel.xyz (could be debug, could be text)
                                relIndices.add((int) i);
                            }
                            default -> {}
                        }
                    }
                    // Navigate to .strtab
                    byte[] strings = null;
                    if (strtab_idx > 0) {
                        var shstr = sectionHeaders.get(strtab_idx);
                        in.seek(shstr.off);
                        strings = new byte[shstr.size];
                        in.readFully(strings, 0, shstr.size);
//                        for(int off : undefined_name_offsets) {
//                            undefined.add(ThreeDSUtils.getName(strings,off));
//                        }
                    }
                    // Concatenate all text data
//                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
//                    for (byte[] ba : textData) {
//                        baos.write(ba);
//                    }
//                    bin_bytes = baos.toByteArray();

                    // Only keep .text data (most of the rest is debug-related)
                    var shstrtab = sectionHeaders.get(eh.shstrndx);
                    in.seek(shstrtab.off);
                    byte[] shstrings = new byte[shstrtab.size];
                    in.readFully(shstrings, 0, shstrtab.size);
                    for (Integer off : textNameOffsets) {
                        String name = ThreeDSUtils.getName(shstrings, off);
                        if (name.equals(".text")) {
                            bin_bytes = textData.get(textNameOffsets.indexOf(off));
                            break;
                        }
                    }
                    if (bin_bytes == null) throw new Exception(String.format(
                            "No .text section in %s!",path.getFileName()));
                    mask = new byte[bin_bytes.length];
                    Arrays.fill(mask, (byte) 0xff);
                    // Will also need .rel.text, though, for relocations
                    for (Integer i : relIndices) {
                        SectionHeaderEntry relsh = sectionHeaders.get(i);
                        String relsh_name = ThreeDSUtils.getName(shstrings, relsh.name_off);
                        if (relsh_name.equals(".rel.text")) {
                            in.seek(relsh.off);
                            var re = new RelocationEntry(in);
                            var sym = symtabEntries.get(re.sym_idx);
                            // strings technically shouldn't be null at this point;
                            //  that is, not if relocations exist!
                            String re_name = ThreeDSUtils.getName(
                                    Objects.requireNonNull(strings), sym.name_off);
                            undefined.add(re_name);
                            setMask(re, mask);
                            break;
                        }
                    }
                }
                // Try to find bytes in currentProgram
                List<Address> found = findAll(bin_bytes, mask);
                if (found.isEmpty()) {
                    printf("Binary file \"%s\" was not found in \"%s\"!\n",
                            path.getFileName(), currentProgram.getName());
                    continue;
                } else if (found.size() > 1) {
                    printf("Multiple addresses found for %s:\n", path.getFileName());
                    for (Address a : found) {
                        printf("\t%s\n", a);
                    }
                    boolean splitMult = askYesNo("Split all matches?",
                            String.format("Found %d matches. Continue with all matches?", found.size()));
                    if (!splitMult) continue;
                }
                // Matches >= 1
                for (Address start : found) {
                    Address end = start.add(bin_bytes.length - 1);
                    matches.add(new AddressPair(start, end));
                }
            }
        }
        // Next, find the interstitial space
        List<AddressPair> toObjectify = new ArrayList<>();
        matches.sort(Comparator.comparing(a -> a.start));
        Address start = currentProgram.getMinAddress();
        while (!matches.isEmpty()) {
            AddressPair p = matches.removeFirst();
            if (p.start.compareTo(start) > 0) {
                // Plan new object ending just before p.start
                toObjectify.add(new AddressPair(start,p.start.subtract(1)));
            }
            start = p.end.add(1);
        }
        // Plan final object for end of binary
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
//        MemoryBlock textBlock = Arrays.stream(blocks)
//                .filter(b -> b.getName().equals(".text"))
//                .findFirst()
//                .orElseThrow();
        MemoryBlock rodataBlock = Arrays.stream(blocks)
                .filter(b -> b.getName().equals(".rodata"))
                .findFirst().orElseThrow();
        MemoryBlock dataBlock = Arrays.stream(blocks)
                .filter(b -> b.getName().equals(".data"))
                .findFirst().orElseThrow();
        // Concatenate remaining blocks
        toObjectify.add(new AddressPair(start, rodataBlock.getStart().subtract(1)));
        toObjectify.add(new AddressPair(rodataBlock.getStart(), dataBlock.getStart().subtract(1)));
        toObjectify.add(new AddressPair(dataBlock.getStart(), dataBlock.getEnd()));

        // Finally, create object files
        for (AddressPair p : toObjectify) {
            File ofile = new File(split_dir, p.start.toString() + ".o");
            int counter = 1;
            while (ofile.exists()) {
                // Same address; increment
                ofile = new File(split_dir, p.start + "_" + counter + ".o");
                counter++;
            }
            try (RandomAccessFile out = new RandomAccessFile(ofile, "rw")) {
                createObjectFile(p.start, p.end, out);
            }
        }
    }

    class AddressPair {
        Address start, end;
        AddressPair(Address start, Address end) {
            this.start = start;
            this.end = end;
        }
    }

    List<Address> findAll(byte[] bytes, byte[] masks) {
        List<Address> found = new ArrayList<>();
        Address start = currentProgram.getMinAddress();
        while(start != null) {
            start = currentProgram.getMemory().findBytes(start, bytes, masks, true, monitor);
            if (start != null) {
                found.add(start);
                start = start.next();
            }
        }
        return found;
    }

    String bytes2str(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("\\x%02X", b & 0xFF));
        }
        return sb.toString();
    }

    // 'end' will be considered within object
    void createObjectFile(Address start, Address end, RandomAccessFile out) throws Exception {
        // Header
        new ELFHeader().write(out);
        // Text
        long text_off = out.getFilePointer();
        out.write(getBytes(start, (int) end.subtract(start) + 1));
        // shstrtab
        long shstrtab_off = out.getFilePointer();
        long text_size = shstrtab_off - text_off;
        out.write(new byte[]{0});
        out.write(".text\0".getBytes(StandardCharsets.UTF_8));
        out.write(".shstrtab\0".getBytes(StandardCharsets.UTF_8));
        // Section Entries
        long sh_off = out.getFilePointer();
        long shstrtab_size = sh_off - shstrtab_off;
        SectionHeaderEntry sh_null = new SectionHeaderEntry(0,0,0,0,0,0);
        sh_null.write(out);
        SectionHeaderEntry sh_text = new SectionHeaderEntry(1,1,0x6, (int) start.getOffset(),(int)text_off,(int)text_size);
        sh_text.write(out);
        SectionHeaderEntry sh_strs = new SectionHeaderEntry(3,3,0,0,(int)shstrtab_off,(int)shstrtab_size);
        sh_strs.write(out);

        // Fix header:
        out.seek(0x20);
        writeIntLE(out,(int)sh_off); // shoff
        out.seek(0x30);
        out.write(new byte[]{3, 0}); // shnum (three sections)
        out.write(new byte[]{2, 0}); // shstrndx (shstrtab is section 2)
    }

    void writeIntLE(RandomAccessFile out, int val) throws IOException {
        out.write((byte)(val & 0xff));
        out.write((byte)((val >> 8) & 0xff));
        out.write((byte)((val >> 16) & 0xff));
        out.write((byte)(val >> 24));
    }

    void writeShortLE(RandomAccessFile out, short val) throws IOException {
        out.write((byte)(val & 0xff));
        out.write((byte)(val >> 8));
    }

    short readShortLE(RandomAccessFile in) throws IOException {
        short val = (short) (in.readByte() & 0xff);
        val |= (short) ((in.readByte() & 0xff) << 8);
        return val;
    }

    int readIntLE(RandomAccessFile in) throws IOException {
        int val = in.readByte() & 0xff;
        val |= (in.readByte() & 0xff) << 8;
        val |= (in.readByte() & 0xff) << 16;
        val |= (in.readByte() & 0xff) << 24;
        return val;
    }

    class ELFHeader {

        int shoff;
        short shnum, shstrndx;

        ELFHeader() {}

        ELFHeader(RandomAccessFile in) throws IOException {
            in.seek(0x20);
            shoff = readIntLE(in);
            in.seek(0x30);
            shnum = readShortLE(in);
            shstrndx = readShortLE(in);
        }

        void write(RandomAccessFile out) throws IOException {
            out.write(indent);
            out.write(t_m_v);
            out.write(zero_int); // entry
            out.write(zero_int); // phoff
            out.write(zero_int); // shoff 0x20 (update manually)
            out.write(flags); // flags?
            out.write(ehsize);
            out.write(zero_int); // phentsize, phnum
            writeShortLE(out, shentsize);
            out.write(zero_int); // shnum, shstrndx (update manually)
        }

        final byte[] indent = {0x7f, 'E', 'L', 'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        final byte[] t_m_v = {1, 0, 0x28, 0, 1, 0, 0, 0};
        final byte[] ehsize = {0x34, 0};
        final short shentsize = 0x28;
        final byte[] flags = {0, 0, 0, 5};
        final byte[] zero_int = {0, 0, 0, 0};
    }

    class SectionHeaderEntry {

        SectionHeaderEntry(RandomAccessFile in) throws IOException {
            name_off = readIntLE(in);
            type = readIntLE(in);
            flags = readIntLE(in);
            addr = readIntLE(in);
            off = readIntLE(in);
            size = readIntLE(in);
            link = readIntLE(in);
            info = readIntLE(in);
            addralign = readIntLE(in);
            entsize = readIntLE(in);
        }

        SectionHeaderEntry(int name_off, int type, int flags, int addr, int off, int size) {
            this.name_off = name_off;
            this.type = type;
            this.flags = flags;
            this.addr = addr;
            this.off = off;
            this.size = size;
        }

        void write(RandomAccessFile out) throws IOException {
            writeIntLE(out, name_off);
            writeIntLE(out, type);
            writeIntLE(out, flags);
            writeIntLE(out, addr);
            writeIntLE(out, off);
            writeIntLE(out, size);
            writeIntLE(out, link);
            writeIntLE(out, info);
            if (name_off == 0) writeIntLE(out, 0);
            else writeIntLE(out, addralign);
            writeIntLE(out, entsize);
        }

        int name_off;
        int type;
        int flags;
        int addr;
        int off;
        int size;
        int link = 0;
        int info = 0;
        int addralign = 0x4;
        int entsize = 0;
    }

    class SymbolTableEntry {

        int name_off;
        int value;
        int size;
        byte info;
        byte other;
        int shndx;

        SymbolTableEntry(RandomAccessFile in) throws IOException {
            name_off = readIntLE(in);
            value = readIntLE(in);
            size = readIntLE(in);
            info = in.readByte();
            other = in.readByte();
            shndx = readIntLE(in);
        }

        SymbolTableEntry(int name_off, int value, int size, byte info, byte other, int shndx) {
            this.name_off = name_off;
            this.value = value;
            this.size = size;
            this.info = info;
            this.other = other;
            this.shndx = shndx;
        }

        void write(RandomAccessFile out) throws IOException {
            writeIntLE(out, name_off);
            writeIntLE(out, value);
            writeIntLE(out, size);
            writeIntLE(out, info);
            writeIntLE(out, other);
            writeIntLE(out, shndx);
        }
    }

    enum RelocationType {
        R_ARM_NONE((byte) 0),
        R_ARM_ABS32((byte) 2),
        R_ARM_REL32((byte) 3),
        R_ARM_THM_PC22((byte) 10),
        R_ARM_CALL((byte) 28),
        R_ARM_JUMP24((byte) 29),
        R_ARM_TARGET1((byte) 38),
        R_ARM_PREL31((byte) 42);

        final byte i;
        private static final Map<Byte, RelocationType> BY_VALUE = new HashMap<>();

        static {
            for (RelocationType t : values()) {
                BY_VALUE.put(t.i, t);
            }
        }

        RelocationType(byte i) {
            this.i = i;
        }

        static RelocationType typeOf(byte b) {
            RelocationType type = BY_VALUE.get(b);
            if (type == null) {
                throw new IllegalArgumentException("Unknown relocation type: " + b);
            }
            return type;
        }
    }

    void setMask(RelocationEntry re, byte[] mask) {
        switch(re.type) {
            case R_ARM_CALL -> {
                mask[re.off] = 0x00;
                mask[re.off + 1] = 0x00;
                mask[re.off + 2] = 0x00;
            }
            default -> {}
        }
    }

    class RelocationEntry {

        int off;
        int sym_idx;
        RelocationType type;

        RelocationEntry(RandomAccessFile in) throws IOException {
            off = readIntLE(in);
            int tmp = readIntLE(in);
            sym_idx = tmp >> 8;
            type = RelocationType.typeOf((byte) (tmp & 0xff));
        }

        RelocationEntry(int off, int sym_idx, RelocationType type) {
            this.off = off;
            this.sym_idx = sym_idx;
            this.type = type;
        }

        void write(RandomAccessFile out) throws IOException {
            writeIntLE(out, off);
            int tmp = sym_idx << 8;
            tmp |= type.i & 0xff;
            writeIntLE(out,tmp);
        }
    }
}
