// Why do some CRO PLT entries have no import record, when the file lists one for them?
//
// For a sample of the entries the symbol export names only by address, prints what Ghidra
// holds on the stub and its literal word: instruction, function, every reference (of any
// kind, with source), every symbol (with source). Then, for the code.bin address the file
// says each one imports, what code.bin has there -- in case the record went missing because
// the target could not be named. Read-only.
//
//@category 3DS

import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class DiagnoseLostImports extends GhidraScript {

    // module -> { stub address, code.bin address the file's import names }
    // The 643 CRO PLT entries with no export row all import a code.bin destructor that has a
    // D1/D2 alias pair. A sample of those first, then two of the older "no import record" ones.
    private static final Object[][] CASES = {
            {"ModuleAmiiboCamera.cro", 0x32cL, 0x1cb8fcL},   // _ZN11InOutWindowD1Ev
            {"ModuleAmiiboCamera.cro", 0x904L, 0x2704e4L},   // _ZN14NfcErrorReceptD2Ev
            {"ModuleAmiiboCamera.cro", 0xdb4L, 0x55ceb8L},   // _ZN4sead6ThreadD2Ev
            {"ModuleAmiiboCamera.cro", 0xc14L, 0x317e2cL},   // _ZN3g3d14ResourceLoaderD1Ev
            {"ModuleMiniGame0.cro", 0x4a0L, 0x306978L},
            {"ModuleKappei.cro", 0x5c8L, 0x5c458cL},
    };

    @Override
    protected void run() throws Exception {
        Map<String, Program> open = new HashMap<>();
        try {
            for (Object[] c : CASES) {
                String mod = (String) c[0];
                Program p = open.get(mod);
                if (p == null) {
                    // An optional script argument names the folder to search (headless runs
                    // on a scratch copy); otherwise the whole project, first match wins.
                    DomainFolder under = state.getProject().getProjectData().getRootFolder();
                    if (getScriptArgs().length > 0) {
                        DomainFolder f0 = state.getProject().getProjectData()
                                .getFolder(getScriptArgs()[0]);
                        if (f0 != null) under = f0;
                    }
                    DomainFile f = find(under, mod);
                    if (f == null) { println(mod + ": not in project"); continue; }
                    p = (Program) f.getDomainObject(this, true, false, monitor);
                    open.put(mod, p);
                }
                Address stub = addr(p, (Long) c[1]);
                println(String.format("=== %s %s (imports code.bin 0x%x)", mod, stub, (Long) c[2]));
                describe(p, stub);
                describe(p, stub.add(4));
                // A neighbour that did get its record, for comparison.
                println("  -- neighbour:");
                describe(p, stub.add(12));
                Address t = addr(currentProgram, (Long) c[2] & ~1L);
                StringBuilder sb = new StringBuilder("  code.bin target " + t + ":");
                for (Symbol s : currentProgram.getSymbolTable().getSymbols(t)) {
                    sb.append(String.format(" [%s %s %s]", s.getName(true), s.getSource(),
                            s.getSymbolType()));
                }
                Function tf = currentProgram.getFunctionManager().getFunctionAt(t);
                sb.append(tf == null ? " no function" : " function " + tf.getName(true)
                        + (tf.isThunk() ? " THUNK" : ""));
                println(sb.toString());
            }
            // How the module's external library records this target, if at all.
        } finally {
            for (Program p : open.values()) p.release(this);
        }
    }

    private void describe(Program p, Address a) {
        Instruction ins = p.getListing().getInstructionAt(a);
        Function f = p.getFunctionManager().getFunctionAt(a);
        if (f != null) {
            println(String.format("      function: thunk=%s primary=%s symbolName=%s ns=%s body=%s",
                    f.isThunk(), f.getSymbol().isPrimary(), f.getSymbol().getName(),
                    f.getParentNamespace().getName(true), f.getBody()));
        }
        StringBuilder sb = new StringBuilder(String.format("    %s: %s%s", a,
                ins == null ? "(no instruction)" : ins.toString(),
                f == null ? "" : "  FUNCTION " + f.getName(true) + " src " + f.getSymbol().getSource()));
        for (Reference r : p.getReferenceManager().getReferencesFrom(a)) {
            if (r instanceof ExternalReference x) {
                sb.append(String.format("  EXT[%s label=%s addr=%s src=%s type=%s op=%d]",
                        x.getLibraryName(), x.getExternalLocation().getLabel(),
                        x.getExternalLocation().getAddress(), r.getSource(),
                        r.getReferenceType(), r.getOperandIndex()));
            } else {
                sb.append(String.format("  ref[->%s %s src=%s op=%d]", r.getToAddress(),
                        r.getReferenceType(), r.getSource(), r.getOperandIndex()));
            }
        }
        println(sb.toString());
        for (Symbol s : p.getSymbolTable().getSymbols(a)) {
            println(String.format("        sym %s %s %s", s.getName(true), s.getSource(),
                    s.getSymbolType()));
        }
    }

    private static Address addr(Program p, long off) {
        return p.getAddressFactory().getDefaultAddressSpace().getAddress(off);
    }

    private DomainFile find(DomainFolder folder, String name) {
        DomainFile f = folder.getFile(name);
        if (f != null) return f;
        for (DomainFolder sub : folder.getFolders()) {
            f = find(sub, name);
            if (f != null) return f;
        }
        return null;
    }
}
