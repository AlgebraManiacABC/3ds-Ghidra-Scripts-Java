//@category 3DS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class Unthunk extends GhidraScript {
    @Override
    protected void run() throws Exception {
        FunctionManager fman = currentProgram.getFunctionManager();
        FunctionIterator iter =  fman.getFunctions(true);
        while (iter.hasNext()) {
            Function f = iter.next();
            if (f.isThunk() && !f.getName().contains(
                    f.getSymbol().getAddress().toString())) {
                Symbol sym = f.getSymbol();
                sym.setName(sym.getName() + "_" + sym.getAddress().toString(), SourceType.DEFAULT);
            }
        }
    }
}
