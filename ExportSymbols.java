//@category 3DS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.Objects;

public class ExportSymbols extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Register tmode = currentProgram.getProgramContext().getRegister("TMode");

        File outFile = askFile("Output file", "OK");
        PrintWriter out = new PrintWriter(new FileWriter(outFile));
        out.println("Location,Name,Mode,Size");

        boolean unique = askYesNo("Create unique symbols?","Should the script export each symbol with a unique name (including the symbol address)?");

        FunctionManager fm = currentProgram.getFunctionManager();
        Iterator<Symbol> iter = currentProgram.getSymbolTable().getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol symbol = iter.next();
            if (!symbol.isPrimary() || symbol.isExternal()) continue;
            Address addr = symbol.getAddress();
            String name = symbol.getName(true);
            String mode = null;
            CodeUnit cu = currentProgram.getListing().getCodeUnitAt(addr);
            if (cu instanceof Instruction) {
                Function f = fm.getFunctionAt(addr);
                if (f == null) continue;
                if (f.isThunk()) name += "_" + addr;
                var rv = currentProgram.getProgramContext().getRegisterValue(tmode, addr);
                if (rv != null) {
                    BigInteger val = rv.getUnsignedValue();
                    mode = Objects.equals(val, BigInteger.ONE) ? "$t" : "$a";
                }
            } else if (cu instanceof Data) {
                mode = "$d";
            }
            if (mode == null) continue;
            if (unique && !name.contains(addr.toString())) {
                name += "_" + addr;
            }
            Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
            long size = func != null ? func.getBody().getNumAddresses() : 0;
            out.println(String.format("\"%s\",\"%s\",%s,%08x",addr,name,mode,size));
        }

        out.close();
        println("Done!");
    }
}
