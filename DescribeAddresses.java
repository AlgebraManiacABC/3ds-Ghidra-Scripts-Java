// Print what the program holds at each address given as a script argument (hex): the block
// and whether it is initialized, the code unit, the function, and every symbol with its
// namespace, source and primary flag. Read-only; for headless inspection.
//
//@category 3DS

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class DescribeAddresses extends GhidraScript {
    @Override
    protected void run() throws Exception {
        for (String arg : getScriptArgs()) {
            Address a = toAddr(Long.parseLong(arg.replace("0x", ""), 16));
            MemoryBlock b = currentProgram.getMemory().getBlock(a);
            CodeUnit cu = currentProgram.getListing().getCodeUnitAt(a);
            Function f = getFunctionAt(a);
            Function in = getFunctionContaining(a);
            if (in != null && f == null) {
                println(String.format("   (inside %s @ %s, body %s)", in.getName(true),
                        in.getEntryPoint(), in.getBody()));
            }
            println(String.format("== %s block=%s init=%s exec=%s cu=%s func=%s", a,
                    b == null ? "none" : b.getName(), b != null && b.isInitialized(),
                    b != null && b.isExecute(), cu == null ? "null" : cu.getClass().getSimpleName()
                            + ":" + cu, f == null ? "none" : f.getName(true) + (f.isThunk() ? " THUNK" : "")));
            for (Symbol s : currentProgram.getSymbolTable().getSymbols(a)) {
                println(String.format("     sym %s ns=%s src=%s primary=%s type=%s", s.getName(),
                        s.getParentNamespace().getName(true), s.getSource(), s.isPrimary(),
                        s.getSymbolType()));
            }
            for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(a)) {
                println("     ref " + r);
            }
        }
    }
}
