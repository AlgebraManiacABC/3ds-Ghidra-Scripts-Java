//@category Tests
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.SourceType;

/**
 * Breaks the thunk relationship on every thunk function in the program, so each
 * one becomes an ordinary standalone function.
 *
 * A thunk borrows its name, signature and namespace from the function it points
 * at. The borrowed signature is copied onto the function so it survives, but the
 * borrowed name is dropped: each unthunked function reverts to its default
 * FUN_xxxxxxxx label.
 *
 * Thunks to external (imported) functions are how Ghidra ties a call site to a
 * library import, so those are left alone unless you ask otherwise.
 */
public class RemoveAllThunks extends GhidraScript {

    @Override
    protected void run() throws Exception {
        boolean includeExternals = askYesNo("Remove All Thunks",
                "Also unthunk thunks that point at external (imported) functions?\n" +
                "Saying yes breaks the link between call sites and the library import.");

        int unthunked = 0;
        int skippedExternal = 0;
        int failed = 0;

        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        while (iter.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            Function f = iter.next();
            if (!f.isThunk()) {
                continue;
            }

            Function thunked = f.getThunkedFunction(true);
            if (thunked != null && thunked.isExternal() && !includeExternals) {
                skippedExternal++;
                continue;
            }

            String inheritedName = f.getName();
            FunctionDefinitionDataType sig = new FunctionDefinitionDataType(f, true);

            try {
                f.setThunkedFunction(null);
                // NO_CHANGE matters here: the shorter constructors default to
                // RENAME_IF_DEFAULT, which would notice the freshly defaulted
                // symbol and put the thunked function's name straight back on.
                new ApplyFunctionSignatureCmd(f.getEntryPoint(), sig, SourceType.USER_DEFINED,
                        false, false, DataTypeConflictHandler.DEFAULT_HANDLER,
                        FunctionRenameOption.NO_CHANGE).applyTo(currentProgram, monitor);
                f.setName(null, SourceType.DEFAULT);
            } catch (Exception e) {
                printf("Could not unthunk %s at %s: %s\n",
                        inheritedName, f.getEntryPoint(), e.getMessage());
                failed++;
                continue;
            }

            printf("Unthunked %s at %s -> %s\n",
                    inheritedName, f.getEntryPoint(), f.getName());
            unthunked++;
        }

        printf("Done: %d unthunked, %d external thunks left alone, %d failed.\n",
                unthunked, skippedExternal, failed);
    }
}
