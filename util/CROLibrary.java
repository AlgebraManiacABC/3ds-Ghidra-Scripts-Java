package util;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SourceType;

public class CROLibrary {
    Library library;
    DomainFile croFile;
    SegmentBlock[] segments;
    String name;

    public CROLibrary(DomainFile croFile, Program program, ProgramManager pman) throws Exception {
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

    public String getName() { return name; }
}
