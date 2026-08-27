//@category RTTI

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

import static util.Demangler.DemangleAndNameNamespace;

public class DemangleRTTIString extends GhidraScript {
    @Override
    protected void run() throws Exception {
        AddressSetView selection = currentSelection;
        if (selection != null) {
            for (AddressRange ar : selection) {
                for (Address addr : ar) {
                    if (getDataAt(addr) == null) continue;
                    demangleAt(addr);
                }
            }
        } else {
            demangleAt(currentAddress);
        }
    }

    private void demangleAt(Address addr) throws Exception {
        if (getDataAt(addr).getValue() instanceof String name) {
            Symbol symbol = getSymbolAt(addr);
            if (symbol == null) {
                symbol = createLabel(addr, name, true);
            }
            String mangled = String.format("_ZTS%s",name);
            symbol.setName(mangled, SourceType.DEFAULT);
            DemangleAndNameNamespace(currentProgram, addr, monitor,false, false);
        } else {
            printf("The data at %s is not a String!\n", addr);
        }
    }
}
