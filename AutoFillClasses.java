//@category RTTI
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.util.FillOutStructureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.FunctionParameterFieldLocation;

import java.util.ArrayList;
import java.util.List;

public class AutoFillClasses extends GhidraScript {
    @Override
    protected void run() throws Exception {
        DecompileOptions options = DecompilerUtils.getDecompileOptions(
                state.getTool(), currentProgram);

        // Collect all GhidraClass namespaces
        List<GhidraClass> classes = new ArrayList<>();
        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator iter = symTable.getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            Namespace ns = sym.getParentNamespace();
            if (ns instanceof GhidraClass gc && !classes.contains(gc)) {
                classes.add(gc);
            }
        }

        int totalClasses = classes.size();
        int filled = 0;
        int skipped = 0;
        int failed = 0;

        for (int c = 0; c < totalClasses; c++) {
            if (monitor.isCancelled()) break;
            GhidraClass gc = classes.get(c);
            monitor.setProgress(c);
            monitor.setMaximum(classes.size());
            monitor.setMessage(String.format("[%d/%d] %s", c + 1, classes.size(),
                    gc.getName(true)));

            // Get all functions in this class namespace
            SymbolIterator classSyms = symTable.getSymbols(gc);
            while (classSyms.hasNext()) {
                Symbol sym = classSyms.next();
                if (sym.getSymbolType() != SymbolType.FUNCTION) continue;

                Function func = getFunctionAt(sym.getAddress());
                if (func == null) continue;

                switch (autoFillClassStructure(func, options)) {
                    case -1 -> failed++;
                    case 0 -> filled++;
                    case 1 -> skipped++;
                }
            }
        }

        println("\n=== SUMMARY ===");
        println("Total classes:  " + totalClasses);
        println("Filled:           " + filled);
        println("Skipped:          " + skipped);
        println("Failed:           " + failed);
    }

    // 0=success, 1=skipped, -1=failed
    private int autoFillClassStructure(Function func, DecompileOptions options) {
        if (!"__thiscall".equals(func.getCallingConventionName()))
            return 1;

        Namespace ns = func.getParentNamespace();
        if (!(ns instanceof GhidraClass))
            return 1; // Skipped

        Parameter thisParam = func.getParameter(0);
        if (thisParam == null)
            return 1;

        try {
            FunctionParameterFieldLocation loc = new FunctionParameterFieldLocation(
                    currentProgram, func.getEntryPoint(), null,
                    0, null, thisParam);


            FillOutStructureCmd cmd = new FillOutStructureCmd(loc, options);
            if (cmd.applyTo(currentProgram, monitor)) {
                return 0;
            } else {
                return -1;
            }
        } catch (Exception e) {
            return -1;
        }
    }
}
