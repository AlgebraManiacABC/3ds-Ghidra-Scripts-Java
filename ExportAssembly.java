//@category 3DS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

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
        instructions.forEach(i -> println(i.toString()));
    }
}
