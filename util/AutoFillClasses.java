package util;

import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.util.FillOutStructureCmd;
import ghidra.app.script.GhidraState;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.FunctionParameterFieldLocation;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;

public class AutoFillClasses {

    public static String fill(Program program, TaskMonitor monitor, GhidraState state) {
        DecompileOptions options = DecompilerUtils.getDecompileOptions(
                state.getTool(), program);

        // Collect all GhidraClass namespaces
        List<GhidraClass> classes = new ArrayList<>();
        SymbolTable symTable = program.getSymbolTable();
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

                Function func = program.getFunctionManager().getFunctionAt(sym.getAddress());
                if (func == null) continue;

                switch (autoFillClassStructure(func, options, program, monitor)) {
                    case -1 -> failed++;
                    case 0 -> filled++;
                    case 1 -> skipped++;
                }
            }
        }

        return "\n=== AUTO-FILL SUMMARY FOR %s ===".formatted(program.getName().toUpperCase()) +
                "\n\tTotal classes:  " + totalClasses +
                "\n\tFilled:           " + filled +
                "\n\tSkipped:          " + skipped +
                "\n\tFailed:           " + failed;
    }

    // 0=success, 1=skipped, -1=failed
    private static int autoFillClassStructure(Function func, DecompileOptions options,
                                              Program program, TaskMonitor monitor) {
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
                    program, func.getEntryPoint(), null,
                    0, null, thisParam);


            FillOutStructureCmd cmd = new FillOutStructureCmd(loc, options);
            if (cmd.applyTo(program, monitor)) {
                return 0;
            } else {
                return -1;
            }
        } catch (Exception e) {
            return -1;
        }
    }
}
