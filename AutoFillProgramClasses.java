//@category RTTI
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.util.FillOutStructureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.FunctionParameterFieldLocation;
import util.AutoFillClasses;

import java.util.ArrayList;
import java.util.List;

public class AutoFillProgramClasses extends GhidraScript {
    @Override
    protected void run() throws Exception {
        AutoFillClasses.fill(currentProgram, monitor, state);
    }
}
