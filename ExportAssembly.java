//@category 3DS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Symbol;

import java.util.ArrayList;
import java.util.List;

public class ExportAssembly extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Function f = getFunctionContaining(currentAddress);
        AddressSetView body = f.getBody();
        List<Instruction> instructions = new ArrayList<>();
        for (AddressRange ar : body) {
            ar.forEach(a -> {
                Instruction i = getInstructionAt(a);
                if (i == null) return;
                instructions.add(i);
            });
        }
        instructions.forEach(i -> {
            String asm = i.toString();
            Address addr = i.getAddress();
            for (int j=0; j < i.getNumOperands(); j++) {
                int o = i.getOperandType(j);
                switch (o) {
                    case OperandType.ADDRESS | OperandType.SCALAR -> {
                        // [DAT_XYZ]
                        String addr_str = i.getDefaultOperandRepresentation(j);
                        String addr_str_cut = addr_str.substring(1, addr_str.length() - 1);
                        asm = asm.replace(addr_str, getSymbolAt(parseAddress(addr_str_cut)).getName());
                    }
                    case OperandType.ADDRESS | OperandType.CODE -> {
                        String addr_str = i.getDefaultOperandRepresentation(j);
                        asm = asm.replace(addr_str, getSymbolAt(parseAddress(addr_str)).getName());
                    }
                }
            }
            Symbol sym = getSymbolAt(addr);
            if (sym != null) {
                println(sym.getName() + ":");
            }
            println(" " + asm);
        });
    }
}
