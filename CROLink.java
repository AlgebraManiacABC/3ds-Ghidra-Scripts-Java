// Links ALL .cro modules with themselves, and with the static binary (using .crs)
// @category 3DS

import java.io.*;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.demangler.*;
import ghidra.framework.model.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import util.CRXLibrary;
import util.ClassLayoutBuilder;
import util.RTTIUtil;
import util.RenameVTableFunctions;

public class CROLink extends GhidraScript {

    private final List<CRXLibrary> crxLibraries = new ArrayList<>();

    @Override
    protected void run() throws Exception {
        // This script will link all .cro files and the static.crs file together.

        // Get pertinent files, and form .crx into proper CRXLibrary objects
        DomainFile codeFile = askDomainFile("Select the static module (code.bin / .code)");
        File crsFile = askFile("Import static.crs","OK");
        DomainFolder croFolder = askProjectFolder("Select the cro directory");
        // Asked now so the long run needs no attention until the Save prompt. The exports
        // read the programs in memory, so they reflect this run whether or not it is saved.
        File exportDir = null;
        boolean exportUnique = false;
        String exportSpelling = ExportSymbols.AS_IS;
        if (askYesNo("Export when done?", "Write the symbol tables and class hierarchy at " +
                "the end of the run, before the Save prompt?")) {
            exportDir = askDirectory("Export directory", "OK");
            exportUnique = askYesNo("Create unique symbols?", "Should the symbol export " +
                    "give each symbol a unique name (including the symbol address)?");
            exportSpelling = askChoice("Name spelling", "Which spelling should the symbol " +
                    "export's Name column use?", List.of(ExportSymbols.AS_IS,
                    ExportSymbols.MANGLED, ExportSymbols.DEMANGLED), ExportSymbols.AS_IS);
        }
        link(codeFile, crsFile, croFolder, exportDir, exportUnique, exportSpelling, null, null);
    }

    /**
     * The whole run with its inputs given, for CROLinkHeadless. {@code layouts} and
     * {@code save} are asked when null, as the GUI run does.
     */
    public void link(DomainFile codeFile, File crsFile, DomainFolder croFolder, File exportDir,
                     boolean exportUnique, String exportSpelling, Boolean layouts, Boolean save)
            throws Exception {
        ProgramManager pman = util.Programs.manager(this);
        boolean shouldSave = false;
        try {
            crxLibraries.add(new CRXLibrary(codeFile, crsFile, pman, monitor));
            for (DomainFile cro : croFolder.getFiles()) {
                CRXLibrary temp = new CRXLibrary(cro, pman, monitor);
                if (temp.isValidCRO0()) {
                    crxLibraries.add(temp);
                }
            }

            for (var crx : crxLibraries) {
                crx.importModules(crxLibraries);
            }
            // Iterate through the list, linking each module to its imports
            for (var crx : crxLibraries) {
                crx.link(crxLibraries);
            }
            CRXLibrary codebin = crxLibraries.getFirst();
            Symbol[] syms = codebin.program.getSymbolTable().getSymbols(codebin.getBaseAddr());
            for (int i = 0; i < syms.length; i++) {
                if (i == 0) syms[i].setName("Entry", SourceType.USER_DEFINED);
                else syms[i].delete();
            }
            // Analyze the VTables (starting with static)
            RTTIUtil rtti = new RTTIUtil(this);
            RenameVTableFunctions renamer = new RenameVTableFunctions(this);
            List<Map<Long, Long>> AllVtableRttiSlots = new ArrayList<>();
            List<Set<Long>> AllTypeinfoAddresses = new ArrayList<>();
            // The renamer clears its maps at the top of every run(), so each module's
            // class graph has to be copied out before the next one starts.
            List<ClassLayoutBuilder.ModuleInfo> moduleInfos = new ArrayList<>();
            for (var crx : crxLibraries) {
                int txId = crx.program.startTransaction("RTTI Discovery Pipeline");
                try {
                    rtti.run(crx.program);
                    AllVtableRttiSlots.add(new HashMap<>(rtti.getVtableRttiSlots()));
                    AllTypeinfoAddresses.add(new HashSet<>(rtti.getTypeinfoAddresses()));
                } finally {
                    crx.program.endTransaction(txId, true);
                }
            }
            for (int i = 0; i < crxLibraries.size(); i++) {
                var crx = crxLibraries.get(i);
                int txId = crx.program.startTransaction("RTTI Discovery Pipeline");
                try {
                    Map<Long, Long> vtableRttiSlots = AllVtableRttiSlots.get(i);
                    Set<Long> typeinfoAddresses = AllTypeinfoAddresses.get(i);
                    if (vtableRttiSlots.isEmpty()) continue;
                    renamer.run(crx.program, vtableRttiSlots, typeinfoAddresses, monitor, state);
                    moduleInfos.add(ClassLayoutBuilder.ModuleInfo.snapshot(crx.program, renamer));
                } finally {
                    crx.program.endTransaction(txId, true);
                }
            }
            // The linker's stubs once more, after analysis has had its turn on every module:
            // something after the rename pipeline turns some PLT entries and veneers back
            // into Ghidra thunks, and this is the last point before the save.
            // PLT entries are named <target>@<module> from the target's current name, so
            // they are named again here, once every module has had its turn: code.bin goes
            // first and would otherwise embed the CROs' names from before their pipelines.
            Map<String, Program> byPath = new HashMap<>();
            for (var crx : crxLibraries) {
                byPath.put(crx.program.getDomainFile().getPathname(), crx.program);
            }
            for (var crx : crxLibraries) {
                int txId = crx.program.startTransaction("Settle linker stubs");
                try {
                    // Inside the transaction: analysis records its task times in the
                    // program's options, and only currentProgram has the script's own
                    // transaction open to cover that write.
                    analyzeChanges(crx.program);
                    println(crx.program.getName() + ": "
                            + RenameVTableFunctions.renamePltEntries(crx.program, byPath::get));
                    println(crx.program.getName() + ": "
                            + RenameVTableFunctions.renameVeneers(crx.program));
                    println(crx.program.getName() + ": "
                            + RenameVTableFunctions.settleLinkerStubs(crx.program));
                } finally {
                    crx.program.endTransaction(txId, true);
                }
            }
            // Step 8: Lay out class structs -- inherited members first, then auto-fill
            // (optional, takes forever). One pass over every module at once: the walk is
            // parents before children, and a base in code.bin has to be finished before
            // the .cro classes deriving from it, so this cannot go module by module.
            // ClassLayoutBuilder opens its own transaction per module.
            boolean doLayouts = (layouts != null) ? layouts : askYesNo("Build Class Layouts?",
                    "Copy inherited members into each class struct and run Auto Fill in " +
                            "Class for all discovered classes? This can take a long time!");
            if (!moduleInfos.isEmpty() && doLayouts) {
                println(new ClassLayoutBuilder(this, state, monitor, moduleInfos).run());
            }
            if (exportDir != null) {
                exportAll(exportDir, exportUnique, exportSpelling);
            }
            // Save or forget progress
            shouldSave = (save != null) ? save : askYesNo("Save?",
                    String.format("%d modules linked successfully!\nDo you want to save? " +
                                    "If not, progress in external libraries will be lost, and this script must be ran again.",
                            crxLibraries.size()));
        } finally {
            // Every library holds a consumer reference on its program. Release
            // them here so an abort partway through construction or linking
            // cannot strand programs open in the project.
            for (CRXLibrary crx : crxLibraries) {
                try {
                    if (crx.program == currentProgram) {
                        // The open program is the tool's to save and close, not ours, so
                        // it gets none of the cleanup -- but the consumer reference this
                        // library took on it is still ours and has to go back. Skipping
                        // the whole branch, as this used to, left one consumer stranded
                        // per run: after two runs DiagnoseOpenPrograms showed code.bin
                        // held by two CRXLibrary instances that no longer existed.
                        crx.releaseOnly();
                        continue;
                    }
                    crx.cleanup(shouldSave);
                } catch (Exception e) {
                    printerr(String.format("Cleanup of %s failed: %s",
                            crx.program, e.getMessage()));
                }
            }
        }
    }

    /**
     * ExportSymbols (code.bin alone, then every module merged) and ExportClassHierarchy,
     * run on the programs as this run left them. Each failure is reported and the rest
     * carry on: an export going wrong must not cost the chance to save.
     */
    private void exportAll(File dir, boolean unique, String spelling) {
        Program codebin = crxLibraries.getFirst().program;
        // Both scripts read "the program" from their state; for this they mean code.bin,
        // whatever the tool happens to have in front.
        GhidraState st = new GhidraState(getState().getTool(), getState().getProject(),
                codebin, null, null, null);
        String project = getState().getProject().getName();
        List<Program> all = new ArrayList<>();
        for (CRXLibrary crx : crxLibraries) all.add(crx.program);

        File codebinCsv = new File(dir, codebin.getName() + ".csv");
        File mergedCsv = new File(dir, project + "-symbols.csv");
        File classesTxt = new File(dir, project + "-classes.txt");
        try {
            ExportSymbols symbols = new ExportSymbols();
            symbols.set(st, getControls());
            symbols.setNamePreference(spelling);
            symbols.exportProgram(codebin, codebinCsv, unique);
            println("Exported " + codebinCsv.getAbsolutePath());
            symbols.exportMerged(all, mergedCsv, unique);
            println("Exported " + mergedCsv.getAbsolutePath());
            symbols.reportForeignRanges();
        } catch (Exception e) {
            printerr("Symbol export failed: " + e);
        }
        try {
            ExportClassHierarchy classes = new ExportClassHierarchy();
            classes.set(st, getControls());
            classes.export(classesTxt, all);
        } catch (Exception e) {
            printerr("Class hierarchy export failed: " + e);
        }
    }
}