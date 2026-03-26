//@category Tests
import ghidra.app.script.GhidraScript;

import static util.Demangler.DemangleAndNameNamespace;

public class DemangleThis extends GhidraScript {
    @Override
    protected void run() throws Exception {
        DemangleAndNameNamespace(currentProgram, currentAddress, monitor);
    }
}
