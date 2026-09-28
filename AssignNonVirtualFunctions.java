// AssignNonVirtualFunctions.java
// Finds each class's non-virtual member functions from the link order, and re-pads the
// vtable placeholders so their names sort the way the functions are actually laid out.
//
// Run after ProcessAllRTTI, which is what puts the VF<nn> / D0 / D1 names in place.
//
// @category RTTI
// @author Claude (for AlgebraManiacABC)

import ghidra.app.script.GhidraScript;
import util.NonVirtualAssigner;

public class AssignNonVirtualFunctions extends GhidraScript {
    @Override
    protected void run() throws Exception {
        new NonVirtualAssigner(this).run(currentProgram);

        println("\n=== All Done ===");
    }
}
