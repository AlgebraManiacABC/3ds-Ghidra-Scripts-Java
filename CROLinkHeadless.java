// Headless driver for CROLink: the answers CROLink would ask for, as arguments.
//
//   -postScript CROLinkHeadless.java <static.crs path> <cro project folder> <export dir> <save>
//
// Run on the static module (code.bin) with -process; it is the static module CROLink links
// against. Class layouts are skipped. The export uses unique names and the mangled spelling,
// the same answers the GUI runs have used.
//
//@category 3DS

import java.io.File;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFolder;

public class CROLinkHeadless extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 4) {
            throw new IllegalArgumentException(
                    "usage: <static.crs> <cro project folder> <export dir> <save true|false>");
        }
        File crs = new File(args[0]);
        DomainFolder croFolder = state.getProject().getProjectData().getFolder(args[1]);
        if (croFolder == null) throw new IllegalArgumentException("no project folder " + args[1]);
        File exportDir = new File(args[2]);
        exportDir.mkdirs();
        boolean save = Boolean.parseBoolean(args[3]);

        CROLink link = new CROLink();
        link.set(getState(), getControls());
        link.link(currentProgram.getDomainFile(), crs, croFolder, exportDir, true,
                ExportSymbols.MANGLED, false, save);
    }
}
