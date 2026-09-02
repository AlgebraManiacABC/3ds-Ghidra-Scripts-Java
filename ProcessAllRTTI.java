// ProcessAllRTTI.java
// Unified RTTI processing pipeline for ACNL / CRO binaries.
//
// Steps:
//   1. Discover all typeinfo structs in .rodata by scanning for
//      __cxxabiv1 vtable pointer values.
//   2. Demangle RTTI name strings (offset 4 of each typeinfo).
//   3. Create typeinfo data types and apply them to each location.
//   4. Discover vtables by scanning .rodata for pointers to the
//      newly parsed typeinfo structs (excluding typeinfo regions).
//   5. Rename vtable function entries using inheritance-aware logic.
//
// @category RTTI
// @author Claude (for AlgebraManiacABC)

import ghidra.app.script.GhidraScript;
import util.RTTIUtil;
import util.RenameVTableFunctions;

import java.util.Map;
import java.util.Set;

public class ProcessAllRTTI extends GhidraScript {
    @Override
    protected void run() throws Exception {
        // Steps 1-4: Discovery, demangling, struct creation, vtable finding
        RTTIUtil rtti = new RTTIUtil(this);
        rtti.run(currentProgram);

        Map<Long, Long> vtableRttiSlots = rtti.getVtableRttiSlots();
        Set<Long> typeinfoAddresses = rtti.getTypeinfoAddresses();

        if (vtableRttiSlots.isEmpty()) {
            println("No vtables discovered. Nothing to rename.");
            return;
        }

        println("\n=== VTable Rename Pipeline ===\n");

        // Step 5: Rename vtable functions
        RenameVTableFunctions renamer = new RenameVTableFunctions(this);
        renamer.run(currentProgram, vtableRttiSlots, typeinfoAddresses, monitor, state);

        println("\n=== All Done ===");
    }
}