// Prints the function body at the cursor: its ranges, byte count, and the
// instructions actually present. Use to tell a real body from a 1-byte one
// left behind by CreateFunctionCmd on undisassembled bytes.
//
//@category Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import util.ThreeDSUtils;

public class PrintFunctionBody extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Address addr = currentAddress;
        if (addr == null) {
            println("No cursor position.");
            return;
        }

        Function func = getFunctionContaining(addr);
        if (func == null) {
            printf("No function at or containing %s\n", addr);
            return;
        }

        AddressSetView body = func.getBody();
        printf("%s at %s%s\n", func.getName(true), func.getEntryPoint(),
                func.isThunk() ? " (thunk)" : "");
        printf("    body: %s\n", body);
        printf("    ranges: %d, bytes: %d\n",
                body.getNumAddressRanges(), body.getNumAddresses());
        for (AddressRange range : body.getAddressRanges()) {
            printf("        %s - %s (%d bytes)\n",
                    range.getMinAddress(), range.getMaxAddress(), range.getLength());
        }

        // What FixFunctionBodies would derive for this function
        AddressSet derived = ThreeDSUtils.deriveFunctionBody(currentProgram, func, monitor);
        printf("    derived: %s (%d bytes, %d ranges)%s\n",
                derived, derived.getNumAddresses(), derived.getNumAddressRanges(),
                derived.getNumAddresses() > body.getNumAddresses()
                        ? "   <- FixFunctionBodies would grow this body" : "");
        if (derived.getNumAddresses() > body.getNumAddresses() && !derived.contains(body)) {
            printf("        note: derived body does not contain the current one, " +
                    "so FixFunctionBodies will skip it\n");
        }

        // Follow the instructions from the entry point, whether or not they are
        // inside the body, so a too-small body is obvious.
        printf("    instructions from entry:\n");
        Instruction instr = getInstructionAt(func.getEntryPoint());
        int count = 0;
        while (instr != null && count < 32) {
            printf("        %s  %s%s\n", instr.getAddress(), instr,
                    body.contains(instr.getAddress()) ? "" : "   <- outside body");
            if (instr.getFlowType().isTerminal()) break;
            instr = instr.getNext();
            count++;
        }
        if (count == 0 && instr == null) {
            println("        (none - address is not disassembled)");
        }
    }
}
