//@category Tests

import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

public class TestForLibraries extends GhidraScript {
    @Override
    protected void run() throws Exception {
        ExternalManager manager = currentProgram.getExternalManager();
        Library testLibrary = manager.addExternalLibraryName("TestLibrary", SourceType.USER_DEFINED);
        manager.setExternalPath("TestLibrary","/CTR-P-EKJA/romfs/DllBag.cro",true);

        DomainFile cro = parseDomainFile("/CTR-P-EKJA/romfs/DllBag.cro");
        if (cro == null) {
            println("Null.");
            return;
        }
        ProgramManager pman = getState().getTool().getService(ProgramManager.class);
        Program crop = pman.openCachedProgram(cro, this);
        Symbol check = crop.getSymbolTable().getSymbols("FUN_00013680").next();
        if (!check.getName().equals("FUN_00013680")) {
            printf("Not found (%s instead)",check.getName());
            crop.release(this);
            return;
        }
        ReferenceManager rman = currentProgram.getReferenceManager();
        rman.addExternalReference(
                toAddr(0x0019a750),
                testLibrary,
                "FUN_00013680",
                check.getAddress(),
                SourceType.USER_DEFINED,
                0,
                RefType.DATA);
        crop.release(this);
        println("Done!");
    }
}
