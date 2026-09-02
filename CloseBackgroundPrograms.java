// Discards programs left open by leaked script consumers.
// Programs open in the tool are closed through the ProgramManager service.
// Consumers owned by the framework (plugins, ProgramCache) are never released:
// releasing those corrupts the tool's refcounting and breaks PluginTool.dispose.
// @category Tests

import ghidra.app.services.ProgramManager;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CloseBackgroundPrograms extends GhidraScript {

    private int discarded = 0, held = 0;
    private List<Program> toolPrograms = new ArrayList<>();
    private ProgramManager pman;

    /**
     * A consumer we are allowed to release on behalf of: our own script code
     * (CRXLibrary and friends), never anything belonging to Ghidra itself.
     */
    private boolean isOurs(Object consumer) {
        if (consumer == this) return false;
        String cls = consumer.getClass().getName();
        return !cls.startsWith("ghidra.") && !cls.startsWith("docking.");
    }

    @Override
    protected void run() throws Exception {
        pman = getState().getTool().getService(ProgramManager.class);
        if (pman != null) {
            toolPrograms = Arrays.asList(pman.getAllOpenPrograms());
        }
        walk(getState().getProject().getProjectData().getRootFolder());
        printf("Discarded %d, %d still held.\n", discarded, held);
    }

    private void walk(DomainFolder folder) {
        for (DomainFile df : folder.getFiles()) {
            // Only returns non-null if something already has it open.
            DomainObject obj = df.getOpenedDomainObject(this);
            if (obj == null) continue;
            try {
                close(df, obj);
            } finally {
                obj.release(this);   // our own, from getOpenedDomainObject
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            walk(sub);
        }
    }

    private void close(DomainFile df, DomainObject obj) {
        if (obj == currentProgram) return;

        // Open in the tool: let the ProgramManager tear it down so the tool's
        // own bookkeeping (ProgramCache, plugins) stays consistent.
        if (toolPrograms.contains(obj)) {
            pman.closeProgram((Program) obj, true);
            println("  closed in tool: " + df.getName());
            return;
        }

        // Held only in the background: leaked script references. Drop those,
        // and leave anything the framework owns alone.
        List<Object> ours = new ArrayList<>();
        for (Object c : obj.getConsumerList()) {
            if (isOurs(c)) ours.add(c);
        }
        // Non-saveable first: kills the save prompt and recovery snapshots.
        if (!ours.isEmpty()) obj.setTemporary(true);
        for (Object c : ours) {
            obj.release(c);
        }

        List<?> remaining = obj.getConsumerList();
        if (remaining.size() <= 1) {   // just us, released by the caller
            discarded++;
        } else {
            held++;
            println("  still held: " + df.getName() + " " + remaining);
        }
    }
}
