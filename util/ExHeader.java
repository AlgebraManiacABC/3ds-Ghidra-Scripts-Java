package util;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static util.ThreeDSUtils.getInt;

public class ExHeader {
    enum CTRSectionType {
        TEXT,
        RODATA,
        DATA,
        BSS
    }

    SegmentBlock textInfo;
    SegmentBlock rodataInfo;
    SegmentBlock dataInfo;
    SegmentBlock bssInfo;

    ExHeader(SegmentBlock textInfo, SegmentBlock rodataInfo,
             SegmentBlock dataInfo, SegmentBlock bssInfo) {
        this.textInfo = textInfo;
        this.rodataInfo = rodataInfo;
        this.dataInfo = dataInfo;
        this.bssInfo = bssInfo;
    }

    public ExHeader(File exhFile, AddressSpace space) throws IOException {
        byte[] exh = ThreeDSUtils.getAllBytes(exhFile);
        List<CTRSectionType> types = new ArrayList<>(List.of(
                CTRSectionType.TEXT,
                CTRSectionType.RODATA,
                CTRSectionType.DATA
        ));
        List<SegmentBlock> infos = new ArrayList<>(4);
        for (long seek=0x10; seek<=0x30; seek += 0x10) {
            int addr = getInt(exh, seek);
            int size = getInt(exh, seek + 0x8);
            CTRSectionType type = types.removeFirst();
            infos.add(new SegmentBlock(space.getAddress(addr), size, type.ordinal()));
        }
        Address bssAddr = infos.getLast().segmentStart.add(infos.getLast().segmentSize);
        long bssSize = getInt(exh, 0x40);

        this.textInfo = infos.removeFirst();
        this.rodataInfo = infos.removeFirst();
        this.dataInfo = infos.removeFirst();
        this.bssInfo = new SegmentBlock(bssAddr, bssSize, CTRSectionType.BSS.ordinal());
    }

    public SegmentBlock[] getSegments() {
        return new SegmentBlock[]{
                textInfo,
                rodataInfo,
                dataInfo,
                bssInfo
        };
    }
}
