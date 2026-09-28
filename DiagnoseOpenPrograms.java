// Read-only. Reports which sources can see open programs, and which cannot.
// CloseBackgroundPrograms only walks the project tree; if that walk comes back
// empty while the tool or the project still report open data, the walk is the
// part that broke, not the release logic.
// @category Tests

import ghidra.app.services.ProgramManager;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.List;

public class DiagnoseOpenPrograms extends GhidraScript {

    private int filesSeen = 0, foldersSeen = 0;
    private final List<DomainFile> walkFoundOpen = new ArrayList<>();

    @Override
    protected void run() throws Exception {
        Project project = getState().getProject();
        println("project: " + (project == null ? "<null>" : project.getName()));
        println("currentProgram: " + (currentProgram == null ? "<null>" : currentProgram.getName()));

        // 1. What the tool thinks is open.
        ProgramManager pman = getState().getTool().getService(ProgramManager.class);
        println("");
        println("--- ProgramManager.getAllOpenPrograms() ---");
        if (pman == null) {
            println("  <no ProgramManager service>");
        } else {
            Program[] open = pman.getAllOpenPrograms();
            println("  count: " + open.length);
            for (Program p : open) {
                println("  " + p.getName() + "  consumers=" + p.getConsumerList());
            }
        }

        // 2. What the project thinks is open. Catches files the naive folder
        //    recursion misses (links, view-only project data, unsaved imports).
        println("");
        println("--- Project.getOpenData() ---");
        try {
            List<DomainFile> openData = project.getOpenData();
            println("  count: " + openData.size());
            for (DomainFile df : openData) {
                DomainObject obj = df.getOpenedDomainObject(this);
                try {
                    println("  " + df.getPathname()
                            + "  opened=" + (obj != null)
                            + (obj == null ? "" : "  consumers=" + obj.getConsumerList()));
                } finally {
                    if (obj != null) obj.release(this);
                }
            }
        } catch (Throwable t) {
            // If this API moved in 12.0 we want to know that specifically.
            println("  FAILED: " + t);
        }

        // 3. What CloseBackgroundPrograms' own walk finds.
        println("");
        println("--- recursive walk of root folder ---");
        DomainFolder root = project.getProjectData().getRootFolder();
        println("  root: " + root.getPathname());
        walk(root);
        printf("  visited %d folders, %d files; %d reported open\n",
                foldersSeen, filesSeen, walkFoundOpen.size());
        for (DomainFile df : walkFoundOpen) {
            println("  open: " + df.getPathname());
        }
    }

    private void walk(DomainFolder folder) {
        foldersSeen++;
        for (DomainFile df : folder.getFiles()) {
            filesSeen++;
            DomainObject obj = df.getOpenedDomainObject(this);
            if (obj == null) continue;
            try {
                walkFoundOpen.add(df);
            } finally {
                obj.release(this);
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            walk(sub);
        }
    }
}
