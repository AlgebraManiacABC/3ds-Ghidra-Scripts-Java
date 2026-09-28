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
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.util.LinkedHashSet;
import java.util.Set;

public class AutoFillClasses {

    /** What one pass of the decompiler's structure filling did. */
    public record Counts(int filled, int skipped, int failed) {
        public static final Counts ZERO = new Counts(0, 0, 0);

        public Counts plus(Counts other) {
            return new Counts(filled + other.filled, skipped + other.skipped,
                    failed + other.failed);
        }

        @Override
        public String toString() {
            return filled + " filled, " + skipped + " skipped, " + failed + " failed";
        }
    }

    public static DecompileOptions optionsFor(GhidraState state, Program program) {
        return DecompilerUtils.getDecompileOptions(state.getTool(), program);
    }

    /**
     * Fill every class in the program, in whatever order the symbol table hands them
     * over. {@link ClassLayoutBuilder} is the better entry point where inheritance is
     * known: filling a derived class before its base means the base's members are
     * rediscovered unnamed in each child, and the decompiler's attempt to place the
     * base subobject at offset 0 is dropped for want of room.
     */
    public static String fill(Program program, TaskMonitor monitor, GhidraState state) {
        DecompileOptions options = optionsFor(state, program);

        // Collect all GhidraClass namespaces
        Set<GhidraClass> classes = new LinkedHashSet<>();
        SymbolTable symTable = program.getSymbolTable();
        SymbolIterator iter = symTable.getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            Namespace ns = sym.getParentNamespace();
            if (ns instanceof GhidraClass gc) {
                classes.add(gc);
            }
        }

        int totalClasses = classes.size();
        Counts totals = Counts.ZERO;

        int c = 0;
        monitor.setMaximum(totalClasses);
        for (GhidraClass gc : classes) {
            if (monitor.isCancelled()) break;
            monitor.setProgress(c);
            monitor.setMessage(String.format("[%d/%d] %s", ++c, totalClasses,
                    gc.getName(true)));
            totals = totals.plus(fillClass(gc, options, program, monitor));
        }

        return "\n=== AUTO-FILL SUMMARY FOR %s ===".formatted(program.getName().toUpperCase()) +
                "\n\tTotal classes:  " + totalClasses +
                "\n\tFilled:           " + totals.filled() +
                "\n\tSkipped:          " + totals.skipped() +
                "\n\tFailed:           " + totals.failed();
    }

    /** Run the decompiler's structure filling over every __thiscall method of one class. */
    public static Counts fillClass(GhidraClass gc, DecompileOptions options,
                                   Program program, TaskMonitor monitor) {
        int filled = 0, skipped = 0, failed = 0;

        SymbolIterator classSyms = program.getSymbolTable().getSymbols(gc);
        while (classSyms.hasNext()) {
            if (monitor.isCancelled()) break;
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
        return new Counts(filled, skipped, failed);
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
            // Swallowing this outright left the failure count as the only evidence that
            // anything went wrong, and no way to tell which function or why.
            Msg.warn(AutoFillClasses.class, "Auto-fill failed for " +
                    func.getName(true) + " at " + func.getEntryPoint() + ": " + e);
            return -1;
        }
    }
}
