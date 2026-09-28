//@category RTTI
import ghidra.app.script.GhidraScript;
import util.AutoFillClasses;

public class AutoFillProgramClasses extends GhidraScript {
    @Override
    protected void run() throws Exception {
        println(AutoFillClasses.fill(currentProgram, monitor, state));
    }
}
