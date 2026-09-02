// Re-derives function bodies by walking flow from the entry point, repairing
// functions that were created before their bytes were disassembled and so ended
// up with a 1-byte body.
//
// Bodies only ever grow: a derived body is applied only when it is a superset of
// the current one, so hand-adjusted bodies are left alone.
//
// Run this before ExportSymbols - the exported Size comes straight from
// Function.getBody().
//
//@category 3DS
//@author AlgebraManiacABC

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import util.ThreeDSUtils;

import java.util.ArrayList;
import java.util.List;

public class FixFunctionBodies extends GhidraScript {

    @Override
    protected void run() throws Exception {
        AddressSetView scope = currentSelection;
        if (scope != null && !scope.isEmpty()) {
            println("Operating on the current selection.");
        } else {
            scope = null;
            println("Operating on the whole program.");
        }

        List<Function> funcs = new ArrayList<>();
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        while (iter.hasNext()) {
            monitor.checkCancelled();
            Function func = iter.next();
            if (func.isExternal() || func.isThunk()) continue;
            if (scope != null && !scope.contains(func.getEntryPoint())) continue;
            funcs.add(func);
        }

        int fixed = 0;
        int skipped = 0;
        int noInstruction = 0;
        int stillTiny = 0;
        long bytesAdded = 0;

        monitor.initialize(funcs.size());
        monitor.setMessage("Fixing function bodies");
        for (Function func : funcs) {
            monitor.checkCancelled();
            monitor.incrementProgress(1);

            Address entry = func.getEntryPoint();
            AddressSetView body = func.getBody();
            long oldSize = body.getNumAddresses();

            if (getInstructionAt(entry) == null) {
                noInstruction++;
                continue;
            }

            AddressSet derived = ThreeDSUtils.deriveFunctionBody(currentProgram, func, monitor);
            long newSize = derived.getNumAddresses();

            if (newSize > oldSize && derived.contains(body)) {
                try {
                    func.setBody(derived);
                    printf("    %s at %s: %d -> %d bytes\n",
                            func.getName(), entry, oldSize, newSize);
                    fixed++;
                    bytesAdded += newSize - oldSize;
                    continue;
                } catch (Exception e) {
                    printf("    SKIP %s at %s: %s\n", func.getName(), entry, e.getMessage());
                    skipped++;
                    continue;
                }
            }

            if (newSize > oldSize) {
                // Derived body disagrees with the existing one rather than extending it.
                printf("    SKIP %s at %s: derived %s does not contain %s\n",
                        func.getName(), entry, derived, body);
                skipped++;
            } else if (oldSize <= 4 && getInstructionAt(entry).getFallThrough() != null) {
                // Suspiciously small and flow continues past it: report so a silent
                // no-op is never mistaken for "nothing to do".
                printf("    UNCHANGED %s at %s: body %s, derived %s\n",
                        func.getName(), entry, body, derived);
                stillTiny++;
            }
        }

        printf("Done! %d fixed (+%d bytes), %d skipped, %d tiny-but-unchanged, " +
                        "%d without instructions, %d examined.\n",
                fixed, bytesAdded, skipped, stillTiny, noInstruction, funcs.size());
    }

}
