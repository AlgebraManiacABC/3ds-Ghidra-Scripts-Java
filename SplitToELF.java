//@category 3DS

import ghidra.app.script.GhidraScript;

import java.io.*;
import java.nio.charset.StandardCharsets;

public class SplitToELF extends GhidraScript {
    @Override
    protected void run() throws Exception {
        File dir = askDirectory("Where to place object files?","OK");
        if (dir == null) return;
        File ofile = new File(dir, "code.o");
        try (RandomAccessFile out = new RandomAccessFile(ofile, "rw")) {
            ELFHeader eh = new ELFHeader();
            // Header
            eh.write(out);
            // Text
            long text_off = out.getFilePointer();
            out.write(new byte[]{0x1e, (byte) 0xff, 0x2f, (byte) 0xe1});
            // Data (test)
            long data_off = out.getFilePointer();
            long text_size = data_off - text_off;
            out.write(new byte[]{(byte) 0xee,0x4a, (byte) 0xd3, (byte) 0xba});
            // shstrtab
            long shstrtab_off = out.getFilePointer();
            long data_size = shstrtab_off - data_off;
            out.write(new byte[]{0});
            out.write(".text\0".getBytes(StandardCharsets.UTF_8));
            out.write(".data\0".getBytes(StandardCharsets.UTF_8));
            out.write(".shstrtab\0".getBytes(StandardCharsets.UTF_8));
            long sh_off = out.getFilePointer();
            long shstrtab_size = sh_off - shstrtab_off;

            SectionHeaderEntry sh_null = new SectionHeaderEntry(0,0,0,0,0,0);
            sh_null.write(out);
            SectionHeaderEntry sh_text = new SectionHeaderEntry(1,1,0x6,0x100000,(int)text_off,(int)text_size);
            sh_text.write(out);
            SectionHeaderEntry sh_data = new SectionHeaderEntry(2, 1, 0x2, 0x200000, (int)data_off, (int)data_size);
            sh_data.write(out);
            SectionHeaderEntry sh_strs = new SectionHeaderEntry(3,3,0,0,(int)shstrtab_off,(int)shstrtab_size);
            sh_strs.write(out);

            out.seek(0x20);
            writeIntLE(out,(int)sh_off); // shoff
            out.seek(0x30);
            out.write(new byte[]{4, 0}); // shnum
            out.write(new byte[]{3, 0}); // shstrndx
        }
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
            out.write(zero_int); // flags
            out.write(ehsize);
            out.write(zero_int); // phentsize, phnum
            out.write(shentsize);
            out.write(zero_int); // shnum, shstrndx (update manually)
        }

        final byte[] indent = {0x7f, 'E', 'L', 'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        final byte[] t_m_v = {1, 0, 0x28, 0, 1, 0, 0, 0};
        byte[] ehsize = {0x34, 0};
        byte[] shentsize = {0x28, 0};
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
