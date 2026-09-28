//@category Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CleanMultipleSymbols extends GhidraScript {
    @Override
    protected void run() throws Exception {
        SymbolTable symTab = currentProgram.getSymbolTable();
        for (Address addr = currentProgram.getMinAddress();
             addr != null && addr.compareTo(currentProgram.getMaxAddress()) <= 0;
             addr = addr.next()) {

            Symbol[] syms = symTab.getSymbols(addr);
            int len = syms.length;
            if (len <= 1) continue;

            List<String> toPrint = new ArrayList<>();
            for (Symbol sym : syms.clone()) {
                String name = sym.getName();
                if (name.startsWith("DAT_")) {
                    sym.delete();
                    len--;
                    if (len > 1) continue;
                    break;
                }
                if (name.startsWith("case") || name.startsWith("default")) continue;
                toPrint.add("\t" + name);
            }
            if (!toPrint.isEmpty()) {
                println(addr + " :\n" + Arrays.toString(toPrint.toArray()));
            }
        }
    }
}
