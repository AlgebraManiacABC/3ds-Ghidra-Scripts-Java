//@category 3DS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.*;

public class ExportSymbols extends GhidraScript {

    class SymbolData {
        Address addr;
        String name;
        String mode;
        long size;

        SymbolData(Address addr, String name, String mode, long size) {
            this.addr = addr;
            this.name = name;
            this.mode = mode;
            this.size = size;
        }

        @Override
        public String toString() {
            return String.format("\"%s\",\"%s\",%s,%08x",addr,name,mode,size);
        }
    }

    @Override
    protected void run() throws Exception {
        Register tmode = currentProgram.getProgramContext().getRegister("TMode");

        File outFile = askFile("Output file", "OK");
        PrintWriter out = new PrintWriter(new FileWriter(outFile));
        out.println("Location,Name,Mode,Size");

        boolean unique = askYesNo("Create unique symbols?","Should the script export each symbol with a unique name (including the symbol address)?");

        Map<String, List<SymbolData>> symbolCounts = new HashMap<>();

        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();
        Iterator<Symbol> iter = currentProgram.getSymbolTable().getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol symbol = iter.next();
            if (!symbol.isPrimary() || symbol.isExternal()) continue;
            Address addr = symbol.getAddress();
            boolean hasExternalRef = Arrays.stream(rm.getReferencesFrom(addr))
                    .anyMatch(Reference::isExternalReference);
            if (hasExternalRef) continue;
            String name = symbol.getName(true);
            String mode = null;
            CodeUnit cu = currentProgram.getListing().getCodeUnitAt(addr);
            Function f = fm.getFunctionAt(addr);
            long size = 0;
            if (cu instanceof Instruction) {
                if (f == null) continue;
                size = f.getBody().getNumAddresses();
                if (f.isThunk()) name += "_" + addr;
                var rv = currentProgram.getProgramContext().getRegisterValue(tmode, addr);
                if (rv != null) {
                    BigInteger val = rv.getUnsignedValue();
                    mode = Objects.equals(val, BigInteger.ONE) ? "$t" : "$a";
                }
            } else if (cu instanceof Data) {
                var d = currentProgram.getListing().getDataAt(addr);
                if (d == null) continue;
                size = d.getDataType().getLength();
                mode = "$d";
            }
            if (mode == null || size <= 0) continue;
            symbolCounts.computeIfAbsent(name, k -> new ArrayList<>()).add(new SymbolData(addr, name, mode, size));
        }

        if (unique) {
            for (List<SymbolData> sdList : symbolCounts.values()) {
                if (sdList.size() > 1) {
                    for (SymbolData sd : sdList) {
                        sd.name += String.format("_%s", sd.addr);
                        out.println(sd);
                    }
                } else {
                    out.println(sdList.getFirst());
                }
            }
        }

        out.close();
        println("Done!");
    }
}
