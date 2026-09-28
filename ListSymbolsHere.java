//@category 3DS

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class ListSymbolsHere extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Symbol[] symbols = currentProgram.getSymbolTable().getSymbols(currentAddress);
        for (Symbol symbol : symbols) {
            println(symbol.getName());
        }

        Reference[] refsFrom = getReferencesFrom(currentAddress);
        for (Reference ref : refsFrom) {
            if (ref instanceof ExternalReference extRef) {
                printf("lib: %s\nlabel: %s\n",extRef.getLibraryName(),extRef.getLabel());
            } else {
                println(ref.toString());
            }
        }
    }
}
