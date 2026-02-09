// Links ALL .cro modules with themselves, and with the static binary (using .crs)
// @category 3DS

import java.io.*;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.demangler.*;
import ghidra.framework.model.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.TimeoutException;
import util.*;

public class CROLink extends GhidraScript {

    private final List<CRXLibrary> crxLibraries = new ArrayList<>();

    @Override
    protected void run() throws Exception {
        // This script will link all .cro files and the static.crs file together.

        // Get pertinent files, and form .crx into proper CRXLibrary objects
        DomainFile codeFile = askDomainFile("Select the static module (code.bin / .code)");
        File crsFile = askFile("Select static.crs","OK");
        DomainFolder croFolder = askProjectFolder("Select the cro directory");
        ProgramManager pman = getState().getTool().getService(ProgramManager.class);
        crxLibraries.add(new CRXLibrary(codeFile, crsFile, pman, monitor));
        for (DomainFile cro : croFolder.getFiles()) {
            CRXLibrary temp = new CRXLibrary(cro, pman, monitor);
            if (temp.isValidCRO0()) {
                crxLibraries.add(new CRXLibrary(cro, pman, monitor));
            }
        }

        for (CRXLibrary crx : crxLibraries) {
            crx.importModules(crxLibraries);
        }
        // Iterate through the list, linking each module to its imports
        for (CRXLibrary crx : crxLibraries) {
            crx.link(crxLibraries);
        }
        // Save or forget progress
        boolean shouldSave = askYesNo("Save?",
                String.format("%d modules linked successfully!\nDo you want to save? " +
                                "If not, progress in external libraries will be lost, and this script must be ran again.",
                        crxLibraries.size()));
        for (CRXLibrary crx : crxLibraries) {
            if (crx.program == currentProgram) continue;
            try {
                crx.cleanup(shouldSave);
            } catch (TimeoutException e) {
                closeProgram(crx.program);
            }
        }
    }
}