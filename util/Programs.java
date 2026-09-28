package util;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Opening another program with or without a tool.
 *
 * <p>In the GUI the tool's ProgramManager caches programs; headless there is no tool, so the
 * project file is opened directly. Both take a consumer reference the caller must release,
 * and both hand back the instance already open if there is one -- the program a headless run
 * is processing included -- so callers need not care which path was taken.
 */
public final class Programs {
    private Programs() {}

    /** The tool's ProgramManager, or null when running headless. */
    public static ProgramManager manager(GhidraScript script) {
        var tool = script.getState().getTool();
        return (tool == null) ? null : tool.getService(ProgramManager.class);
    }

    public static Program open(DomainFile file, Object consumer, ProgramManager pman,
                               TaskMonitor monitor) throws Exception {
        if (file == null) return null;
        if (pman != null) return pman.openCachedProgram(file, consumer);
        return (Program) file.getDomainObject(consumer, true, false, monitor);
    }
}
