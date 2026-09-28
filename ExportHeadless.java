// Headless: the exports CROLink writes at its end, on programs already processed and saved.
//
//   -postScript ExportHeadless.java <cro project folder> <export dir>
//
// Run on the static module (code.bin) with -process -readOnly. Writes code.bin.csv,
// <project>-symbols.csv and <project>-classes.txt, as CROLink does.
//
//@category 3DS

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Program;

public class ExportHeadless extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        DomainFolder croFolder = state.getProject().getProjectData().getFolder(args[0]);
        File dir = new File(args[1]);
        dir.mkdirs();
        List<Program> all = new ArrayList<>();
        all.add(currentProgram);
        List<Program> opened = new ArrayList<>();
        try {
            for (DomainFile f : croFolder.getFiles()) {
                if (!Program.class.isAssignableFrom(f.getDomainObjectClass())) continue;
                Program p = (Program) f.getDomainObject(this, false, false, monitor);
                opened.add(p);
                all.add(p);
            }
            String project = state.getProject().getName();
            ExportSymbols symbols = new ExportSymbols();
            symbols.set(getState(), getControls());
            symbols.setNamePreference(ExportSymbols.MANGLED);
            symbols.exportProgram(currentProgram, new File(dir, currentProgram.getName() + ".csv"), true);
            symbols.exportMerged(all, new File(dir, project + "-symbols.csv"), true);
            symbols.reportForeignRanges();
            ExportClassHierarchy classes = new ExportClassHierarchy();
            classes.set(getState(), getControls());
            classes.export(new File(dir, project + "-classes.txt"), all);
        } finally {
            for (Program p : opened) p.release(this);
        }
    }
}
