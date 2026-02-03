//@category 3DS

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class SplitToELF extends GhidraScript {
    @Override
    protected void run() throws Exception {
        File compiled_bindir = askDirectory("Where are the compiled binaries?","OK");
        if (compiled_bindir == null) return;
        File split_dir = askDirectory("Where to place split object files?","OK");
        if (split_dir == null) return;

        // First, find Addresses with compiled objects
        List<AddressPair> matches = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(compiled_bindir.toPath())) {
            Iterator<Path> iter = stream.iterator();
            while (iter.hasNext()) {
                Path path = iter.next().toAbsolutePath();
                // Read all bytes in compiled binary (not obj, binary from objcopy)
                byte[] bin_bytes = null;
                try (RandomAccessFile in = new RandomAccessFile(path.toFile(), "rw")) {
                    bin_bytes = new byte[(int) in.length()];
                    in.readFully(bin_bytes);
                }
                // Try to find bytes in currentProgram
                List<Address> found = findAll(bin_bytes);
                if (found.isEmpty()) {
                    printf("Binary file \"%s\" was not found in \"%s\"!\n",
                            path.getFileName(),currentProgram.getName());
                    continue;
                } else if (found.size() > 1) {
                    printf("Multiple addresses found for %s:\n",path.getFileName());
                    for (Address a : found) {
                        printf("\t%s\n",a);
                    }
                    boolean splitMult = askYesNo("Split all matches?",
                            String.format("Found %d matches. Continue with all matches?",found.size()));
                    if (!splitMult) continue;
                }
                // Matches >= 1
                for (Address start : found) {
                    Address end = start.add(bin_bytes.length - 1);
                    matches.add(new AddressPair(start,end));
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
        MemoryBlock textBlock = Arrays.stream(blocks)
                .filter(b -> b.getName().equals(".text"))
                .findFirst()
                .orElseThrow();
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

    List<Address> findAll(byte[] bytes) {
        List<Address> found = new ArrayList<>();
        Address start = currentProgram.getMinAddress();
        while(start != null) {
            start = findBytes(start, bytes2str(bytes));
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

    class ELFHeader {
        void write(RandomAccessFile out) throws IOException {
            out.write(indent);
            out.write(t_m_v);
            out.write(zero_int); // entry
            out.write(zero_int); // phoff
            out.write(zero_int); // shoff 0x20 (update manually)
            out.write(flags); // flags?
            out.write(ehsize);
            out.write(zero_int); // phentsize, phnum
            out.write(shentsize);
            out.write(zero_int); // shnum, shstrndx (update manually)
        }

        final byte[] indent = {0x7f, 'E', 'L', 'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        final byte[] t_m_v = {1, 0, 0x28, 0, 1, 0, 0, 0};
        byte[] ehsize = {0x34, 0};
        byte[] shentsize = {0x28, 0};
        byte[] flags = {0, 0, 0, 5};
        final byte[] zero_int = {0, 0, 0, 0};
    }

    class SectionHeaderEntry {
        SectionHeaderEntry(int name_idx, int type, int flags, int addr, int off, int size) {
            this.name_idx = name_idx;
            this.type = type;
            this.flags = flags;
            this.addr = addr;
            this.off = off;
            this.size = size;
        }

        void write(RandomAccessFile out) throws IOException {
            writeIntLE(out, name_idx);
            writeIntLE(out, type);
            writeIntLE(out, flags);
            writeIntLE(out, addr);
            writeIntLE(out, off);
            writeIntLE(out, size);
            writeIntLE(out, link);
            writeIntLE(out, info);
            if (name_idx == 0) writeIntLE(out, 0);
            else writeIntLE(out, addralign);
            writeIntLE(out, entsize);
        }

        int name_idx;
        int type;
        int flags;
        int addr;
        int off;
        int size;
        final int link = 0;
        final int info = 0;
        final int addralign = 0x4;
        final int entsize = 0;
    }
}
