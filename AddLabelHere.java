//@category 3DS

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class AddLabelHere extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentAddress == null) {
            println("No current address; place the cursor somewhere first.");
            return;
        }

        String name = askString("Add Label", "New label for " + currentAddress + ":");
        if (name == null || name.isBlank()) {
            println("No label given.");
            return;
        }
        name = name.trim();

        for (Symbol existing : currentProgram.getSymbolTable().getSymbols(currentAddress)) {
            if (existing.getName().equals(name)) {
                printf("Label \"%s\" already exists at %s\n", name, currentAddress);
                return;
            }
        }

        // createLabel() adds a symbol without disturbing the ones already here
        Symbol added = currentProgram.getSymbolTable().createLabel(currentAddress, name,
            SourceType.USER_DEFINED);
        printf("Added label \"%s\" at %s\n", added.getName(), currentAddress);
    }
}
