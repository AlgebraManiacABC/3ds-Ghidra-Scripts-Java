// Headless helper: copy one project folder into another, or list a folder.
//
//   CopyProjectFolder.java list <folder>
//   CopyProjectFolder.java copy <from folder> <to folder>
//
// "copy" empties <to folder> first (files and subfolders), then copies every file and
// subfolder of <from folder> into it. Folder paths are project paths, e.g. /v1.4-test-base.
//
//@category 3DS

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;

public class CopyProjectFolder extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        DomainFolder root = state.getProject().getProjectData().getRootFolder();
        if (args.length >= 2 && args[0].equals("list")) {
            DomainFolder f = folder(root, args[1], false);
            if (f == null) { println("no folder " + args[1]); return; }
            list(f, "");
            return;
        }
        if (args.length >= 3 && args[0].equals("copy")) {
            DomainFolder from = folder(root, args[1], false);
            if (from == null) throw new IllegalArgumentException("no folder " + args[1]);
            DomainFolder to = folder(root, args[2], true);
            empty(to);
            int n = copy(from, to);
            println("Copied " + n + " files from " + from.getPathname() + " to "
                    + to.getPathname());
            return;
        }
        throw new IllegalArgumentException("usage: list <folder> | copy <from> <to>");
    }

    private DomainFolder folder(DomainFolder root, String path, boolean create)
            throws Exception {
        DomainFolder f = root;
        for (String part : path.split("/")) {
            if (part.isEmpty()) continue;
            DomainFolder next = f.getFolder(part);
            if (next == null) {
                if (!create) return null;
                next = f.createFolder(part);
            }
            f = next;
        }
        return f;
    }

    private void list(DomainFolder f, String indent) {
        println(indent + f.getPathname() + "/");
        for (DomainFile file : f.getFiles()) {
            println(indent + "  " + file.getName() + "  [" + file.getContentType() + "]");
        }
        for (DomainFolder sub : f.getFolders()) list(sub, indent + "  ");
    }

    private void empty(DomainFolder f) throws Exception {
        for (DomainFolder sub : f.getFolders()) {
            empty(sub);
            sub.delete();
        }
        for (DomainFile file : f.getFiles()) file.delete();
    }

    private int copy(DomainFolder from, DomainFolder to) throws Exception {
        int n = 0;
        for (DomainFile file : from.getFiles()) {
            file.copyTo(to, monitor);
            n++;
        }
        for (DomainFolder sub : from.getFolders()) {
            n += copy(sub, to.createFolder(sub.getName()));
        }
        return n;
    }
}
