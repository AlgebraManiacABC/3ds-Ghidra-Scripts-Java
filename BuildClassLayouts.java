// BuildClassLayouts.java
// Single-program version of CROLink's class layout step, for iterating without
// re-running the whole link.
//
// Runs RTTI discovery and the vtable rename pass to build the class graph, then
// gives every class struct the members it inherits and fills in the rest with the
// decompiler -- parents before children, so a base is complete before any class
// derived from it is laid out.
//
// Bases that live in another module cannot be reached from here; use CROLink for
// those.
//
// @category RTTI

import ghidra.app.script.GhidraScript;
import util.ClassLayoutBuilder;
import util.RTTIUtil;
import util.RenameVTableFunctions;

import java.util.List;
import java.util.Map;
import java.util.Set;

public class BuildClassLayouts extends GhidraScript {
    @Override
    protected void run() throws Exception {
        RTTIUtil rtti = new RTTIUtil(this);
        rtti.run(currentProgram);

        Map<Long, Long> vtableRttiSlots = rtti.getVtableRttiSlots();
        Set<Long> typeinfoAddresses = rtti.getTypeinfoAddresses();

        if (vtableRttiSlots.isEmpty()) {
            println("No vtables discovered. Nothing to lay out.");
            return;
        }

        RenameVTableFunctions renamer = new RenameVTableFunctions(this);
        renamer.run(currentProgram, vtableRttiSlots, typeinfoAddresses, monitor, state);

        println(new ClassLayoutBuilder(this, state, monitor,
                List.of(ClassLayoutBuilder.ModuleInfo.snapshot(currentProgram, renamer)))
                .run());
    }
}
