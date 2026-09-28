package util;

import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.TimeoutException;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static util.ThreeDSUtils.*;
import static util.ThreeDSUtils.getInt;
import static util.ThreeDSUtils.getName;
import static util.ThreeDSUtils.getRelocs;

public class CRXLibrary {

    SegmentBlock[] segments;
    byte[] crxBytes;
    String name;
    private final ReferenceManager rman;
    private final TaskMonitor monitor;

    // DO NOT get bytes from this file and expect
    //  to get crx information
    private final DomainFile file;

    public Program program;

    /** Set once cleanup() has dropped our consumer reference on the program. */
    private boolean released = false;

    /**
     * Contains the Library corresponding to the respective
     *   program('s external manager) in the CRXLibrary
     */
    private final HashMap<String, Library> libraries = new HashMap<>();

    public boolean isValidCRO0() {
        if (crxBytes == null) return false;
        // "CRO0" as LE int
        return 0x304F5243 == getInt(crxBytes, 0x80);
    }

    public Address getBaseAddr() {
        if (program == null || segments == null) return null;
        return segments[0].getStart();
    }

    public CRXLibrary(DomainFile codeFile, File crsFile,
               ProgramManager pman, TaskMonitor monitor) throws Exception {
        crxBytes = ThreeDSUtils.getAllBytes(crsFile);
        if (!isValidCRO0()) {
            file = null;
            name = null;
            program = null;
            this.monitor = null;
            segments = null;
            rman = null;
            return;
        }
        // openCachedProgram takes a consumer reference there and then. Everything after it
        // can throw, and a constructor that throws leaves no object for anyone to call
        // cleanup() on -- so the reference would be stranded for the rest of the session,
        // which is the leak Ghidra reports on shutdown.
        Program opened = Programs.open(codeFile, this, pman, monitor);
        SegmentBlock[] segs;
        ReferenceManager refs;
        try {
            segs = ThreeDSUtils.readSegments(crxBytes, opened);
            refs = opened.getReferenceManager();
        } catch (Exception | Error e) {
            opened.release(this);
            throw e;
        }
        file = codeFile;
        name = "|static|";
        program = opened;
        segments = segs;
        rman = refs;
        this.monitor = monitor;
    }

    public CRXLibrary(DomainFile croFile,
               ProgramManager pman, TaskMonitor monitor) throws Exception {
        Program opened = Programs.open(croFile, this, pman, monitor);
        SegmentBlock[] segs;
        ReferenceManager refs;
        // Same reasoning as the constructor above: from here to the last field assignment
        // the consumer reference is held by an object that does not exist yet, so every
        // way out other than success has to give it back by hand.
        try {
            crxBytes = ThreeDSUtils.getAllBytes(opened);
            if (!isValidCRO0()) {
                opened.release(this);
                file = null;
                name = null;
                program = null;
                this.monitor = null;
                segments = null;
                rman = null;
                return;
            }
            segs = ThreeDSUtils.readSegments(crxBytes, opened);
            refs = opened.getReferenceManager();
        } catch (Exception | Error e) {
            opened.release(this);
            throw e;
        }
        file = croFile;
        name = croFile.getName().split("\\.cro")[0];
        program = opened;
        segments = segs;
        rman = refs;
        this.monitor = monitor;
    }

    /**
     * Give back the consumer reference without touching the program otherwise.
     *
     * <p>For the program the tool already has open: saving, unlocking and marking it
     * temporary are the tool's business, but the reference this library took is not, and
     * holding it keeps the program pinned for the rest of the session. Releasing does not
     * close anything -- the tool holds its own consumer.
     */
    public void releaseOnly() {
        if (released) return;
        released = true;
        program.release(this);
    }

    public void cleanup(boolean save) throws Exception {
        // An invalid module never opened a program, and a second cleanup would
        // release a reference we no longer hold.
        if (program == null || released) return;
        try {
            AutoAnalysisManager.getAnalysisManager(program).cancelQueuedTasks();
            AutoAnalysisManager.getAnalysisManager(program).dispose();
            int i;
            for(i=0; program.getCurrentTransactionInfo() != null && i < 60; i++) {
                Thread.sleep(1000);
            }
            if (i == 60) {
                TransactionInfo info = program.getCurrentTransactionInfo();
                String error = String.format(
                        "Program %s hung on transaction: %s (%s) [%d] - forcibly closing",
                        program,info.getDescription(), info.getStatus(), info.getID());
                Msg.error(this,error);
                throw new TimeoutException(error);
            }
            program.clearUndo();
            if (save) {
                program.save("CROLink save", monitor);
            } else {
                if (program.isLocked()) {
                    program.forceLock(true, "CROLink cleanup");
                    program.unlock();
                }
                program.setTemporary(true);
            }
        } finally {
            // Drop our consumer reference no matter how we got here: a save
            // failure or a hung transaction must not strand the program open.
            released = true;
            program.release(this);
        }
    }

    boolean disassemble(Address addr, boolean thumb) {
        var adc = new ArmDisassembleCommand(addr, null, thumb);
        int tx_id = program.startTransaction(String.format("Disassembling %s...",file));
        try {
            adc.applyTo(program, monitor);
        } catch (Exception e) {
            program.endTransaction(tx_id, false);
            throw e;
        }
        program.endTransaction(tx_id, true);
        return (adc.getDisassembledAddressSet() != null);
    }

    // Demangle names
    void demangleAll() throws Exception {
        int tx_id = program.startTransaction("Demangling");
        try {
            var options = new DemanglerOptions();
            options.setApplySignature(true);
            // Snapshot first: the loop adds labels, and a live iterator would visit them.
            List<Symbol> all = new ArrayList<>();
            for (Symbol s : program.getSymbolTable().getAllSymbols(true)) all.add(s);
            for (Symbol mangled : all) {
                if (mangled.isDeleted()) continue;
                Address addr = mangled.getAddress();
                String original = mangled.getName();
                List<DemangledObject> objs = DemanglerUtil.demangle(program, original, addr);
                for (var obj : objs) {
                    boolean applied;
                    try {
                        applied = obj.applyTo(
                                program, addr, new DemanglerOptions(), monitor);
                    } catch (IllegalArgumentException e) {
                        Msg.error(this,String.format("Couldn't apply obj '%s' to addr %s",
                                addr, obj));
                        continue;
                    }
                    if (applied) {
//                        program.getSymbolTable().removeSymbolSpecial(mangled);
                        Function func = program.getFunctionManager().getFunctionAt(addr);
                        if (func != null) {
                            applyFunctionNameHere(
                                    destructorDisplayName(mangled.getName(), obj.getName()),
                                    addr);
                            if (obj.getNamespace() != null) {
                                Namespace ns = NamespaceUtils.createNamespaceHierarchy(
                                        obj.getNamespace().toString(),
                                        null,  // global
                                        program,
                                        SourceType.IMPORTED
                                );
                                moveIntoNamespace(func, addr, ns);
                            }
                            keepMangled(original, addr);
                        }

                        break;
                    }
                }
            }
        } catch (Exception e) {
            program.endTransaction(tx_id, false);
            throw e;
        }
        program.endTransaction(tx_id, true);
    }

    /**
     * Put the module's own mangled spelling back beside the demangled name.
     *
     * <p>The rename above replaces the function's symbol, and with it the one fact the
     * demangled form cannot carry: the full signature. {@code _ZNKSt9exception4whatEv}
     * became {@code std::exception::what}, and the RTTI pipeline, re-deriving a mangled
     * name from that, wrote {@code _ZNSt9exception4whatEv} -- no {@code K}, because
     * const-ness is not in a vtable. An exported name is the linker's own record and is
     * kept verbatim, as an imported label the pipeline will not revise.
     */
    private void keepMangled(String original, Address addr) {
        if (original == null || !original.startsWith("_Z")) return;
        // Only the export table's names. demangleAll walks every _Z symbol, which on a
        // program that has been through the pipeline includes the pipeline's own derived
        // labels; keeping those as IMPORTED froze a whole run's guesses as linker fact, and
        // the next pipeline run refused to revise any of them (1 mangled name added).
        if (!exportedNames.contains(original)) return;
        if ((addr.getOffset() & 1L) == 1) addr = addr.subtract(1);
        SymbolTable st = program.getSymbolTable();
        for (Symbol s : st.getSymbols(addr)) {
            if (s.getName().equals(original)) return;
        }
        try {
            st.createLabel(addr, original, program.getGlobalNamespace(), SourceType.IMPORTED);
        } catch (Exception e) {
            Msg.warn(this, "Could not keep " + original + " at " + addr + ": " + e.getMessage());
        }
    }

    /**
     * Keep the three destructor variants apart in the demangled name.
     *
     * <p>Itanium gives a class three destructors -- D1 complete-object, D0 deleting, D2
     * base-object -- and they are genuinely different functions at different addresses.
     * The standard demangling spells all three {@code ~Class}, so applying it put the same
     * name on both halves of every pair; Ghidra then broke the tie by appending the
     * address, which is where 3,322 {@code ~Class_<addr>} symbols and 1,676
     * identically-named D1/D0 pairs came from. The address suffix carries no meaning and
     * hides which variant is which.
     *
     * <p>D1 keeps the plain spelling because it is the one a source-level {@code ~Class}
     * call reaches. The mangled {@code _ZN..D0Ev} symbol beside it is unchanged and stays
     * the authoritative name.
     */
    static String destructorDisplayName(String mangledName, String demangledName) {
        if (demangledName == null || !demangledName.startsWith("~")) return demangledName;
        if (mangledName == null) return demangledName;
        if (mangledName.endsWith("D0Ev")) return demangledName + "_deleting";
        if (mangledName.endsWith("D2Ev")) return demangledName + "_base";
        return demangledName;
    }

    /**
     * Put a demangled function symbol into its namespace, which is not as simple as asking
     * for it on a program that has been through the pipeline before.
     *
     * <p>{@link RenameVTableFunctions} labels a vtable slot {@code Class::VF06} and writes
     * {@code _ZN5Class4VF06Ev} beside it. On a re-run this loop demangles that mangled
     * label back to name {@code VF06} in namespace {@code Class}, renames the function to
     * {@code VF06}, and then asks to move it into {@code Class} -- where a symbol of that
     * exact name is already sitting at that exact address, so Ghidra refuses with a
     * {@code DuplicateNameException} and the whole run dies. Running twice has to be safe.
     *
     * <p>A symbol with the same name in the same namespace at the same address says
     * precisely what the move is about to say, so it is redundant and goes first. If it
     * cannot be cleared, the function stays where it is: the name is already correct at
     * that address, which is the point of the move.
     */
    private void moveIntoNamespace(Function func, Address addr, Namespace ns) {
        Symbol funcSym = func.getSymbol();
        if (funcSym != null && ns.equals(funcSym.getParentNamespace())) return;

        String name = func.getName();
        for (Symbol other : program.getSymbolTable().getSymbols(addr)) {
            if (funcSym != null && other.getID() == funcSym.getID()) continue;
            if (!name.equals(other.getName())) continue;
            if (!ns.equals(other.getParentNamespace())) continue;
            try {
                other.delete();
            } catch (Exception e) {
                return;
            }
        }
        try {
            func.setParentNamespace(ns);
        } catch (Exception e) {
            Msg.warn(this, String.format("Could not move %s at %s into %s: %s",
                    name, addr, ns.getName(true), e.getMessage()));
        }
    }

    /**
     * A function at an address another module imports from this one's text segment.
     *
     * <p>An import names an exported symbol, and an exported symbol in .text is a function
     * entry, always. The old code made a function only when nothing at all was labelled
     * there, so a Ghidra {@code LAB_} (a branch target it had seen) or {@code DAT_} (a word
     * it had typed as data) won: 37 code.bin addresses that CROs import through 122 PLT
     * entries stayed non-functions, e.g. {@code 0x29b888} and {@code 0x52f0ec}. Data typed
     * over the entry is cleared first, since it is code. The low bit is the Thumb flag.
     */
    private Function ensureExportedFunction(Address addr) {
        boolean thumb = (addr.getOffset() & 1L) == 1;
        Address entry = thumb ? addr.subtract(1) : addr;
        Function f = program.getListing().getFunctionAt(entry);
        if (f != null) return f;
        if (program.getListing().getDefinedDataAt(entry) != null) {
            int tx = program.startTransaction("Clearing data over an exported function");
            try {
                program.getListing().clearCodeUnits(entry, entry, false);
            } finally {
                program.endTransaction(tx, true);
            }
        }
        if (program.getListing().getInstructionAt(entry) == null) disassemble(entry, thumb);
        createFunctionHere(null, entry);
        f = program.getListing().getFunctionAt(entry);
        if (f == null) {
            Msg.warn(this, String.format("%s: could not make a function at exported %s",
                    this.name, entry));
        }
        return f;
    }

    public String getOrCreateNameHere(SegmentOffset segOff) throws Exception {
        Address addr = segOff.getAddr(segments);
        String name;
        if (segOff.getIndex() == SegmentOffset.ID.TEXT) {
            Function f = ensureExportedFunction(addr);
            if (f != null) return f.getSymbol().getName(true);
        }
        Symbol[] symbols = program.getSymbolTable().getSymbols(addr);
        if (symbols.length == 0) {
            // No symbol. Need to create one
            if (segOff.getIndex() == SegmentOffset.ID.TEXT) {
                Address funcAddr = addr;
                if ((addr.getOffset() & 1L) == 1) funcAddr = funcAddr.subtract(1);
                Function func = program.getListing().getFunctionAt(funcAddr);
                if (func != null) return func.getName();
                // Disassemble first, if needed
                boolean disassembled = program.getListing().getInstructionAt(funcAddr) != null;
                if (!disassembled) {
                    disassemble(funcAddr, (addr.getOffset() & 0x1) == 1);
                }
                // Create function, get name
                createFunctionHere(null, funcAddr);
                func = program.getListing().getFunctionAt(funcAddr);
                if (func == null) {
                    return String.format("INVALID_%s_%s",this.name,funcAddr);
                }
                return func.getName();
            } else {
                // Create global var
                int tx_id = program.startTransaction("Creating global variable");
                try {
                    name = "DAT_" + addr;
                    Symbol symbol = program.getSymbolTable()
                            .createLabel(addr, name, SourceType.IMPORTED);
                    name = symbol.getName();
                } catch (Exception e) {
                    program.endTransaction(tx_id, false);
                    throw e;
                }
                program.endTransaction(tx_id, true);
            }
        } else {
            name = symbols[0].getName(true);
        }
        return name;
    }

    boolean applyNameHere(String name, SegmentOffset segOff,
                          Program program) throws Exception {
        Address addr = segOff.getAddr(segments);
        if (addr == null) return false;

        if (segOff.getIndex() == SegmentOffset.ID.TEXT) {
            return applyFunctionNameHere(name, addr);
        } else {
            Symbol check;
            int tx_id = program.startTransaction("Naming address");
            try {
                check = ThreeDSUtils.labelNamedData(name, addr, program);
            } catch (Exception e) {
                program.endTransaction(tx_id, false);
                throw e;
            }
            program.endTransaction(tx_id, true);
            return check != null;
        }
    }

    boolean applyNameHere(String name, SegmentOffset segOff) throws Exception {
        return applyNameHere(name, segOff, program);
    }

    // Assumes program is open
    boolean createFunctionHere(String name, Address addr) {
        var cfc = new CreateFunctionCmd(name, addr, null, SourceType.IMPORTED);
        boolean retVal;
        int tx_id = program.startTransaction("Creating function");
        try {
            retVal = cfc.applyTo(program, monitor);
        } catch (Exception e) {
            program.endTransaction(tx_id, false);
            throw e;
        }
        program.endTransaction(tx_id, true);
        return retVal;
    }

    // Assumes program is open
    boolean applyFunctionNameHere(String name, Address addr) throws Exception {
        boolean thumb = (addr.getOffset() & 0x1) == 1;
        if (thumb) addr = addr.subtract(1);
        Function temp = program.getListing().getFunctionAt(addr);
        // If not a function entrypoint, can we make it one?
        if (temp == null) {
            // Disassemble first: CreateFunctionCmd derives the body from flow, so on
            // undisassembled bytes it produces a 1-byte body that later disassembly
            // never grows.
            if (program.getListing().getInstructionAt(addr) == null) {
                disassemble(addr, thumb);
            }
            createFunctionHere(name, addr);
            temp = program.getListing().getFunctionAt(addr);
        }

        if (temp != null) {
            if (temp.getName().equals(name)) return true;
            // A second name the export table gives the same address is an alias, not a
            // correction: static.crs exports _ZNSsD1Ev and _ZNSsD2Ev both at 0x3076c8, and
            // renaming the function for each left only whichever came last. Keep the first
            // as the function's name and add the other beside it.
            if (temp.getSymbol().getSource() == SourceType.IMPORTED
                    && exportedNames.contains(temp.getName()) && exportedNames.contains(name)) {
                int tx = program.startTransaction("Adding alias export");
                try {
                    boolean present = false;
                    for (Symbol s : program.getSymbolTable().getSymbols(addr)) {
                        if (s.getName().equals(name)) { present = true; break; }
                    }
                    if (!present) {
                        program.getSymbolTable().createLabel(addr, name, SourceType.IMPORTED);
                    }
                } finally {
                    program.endTransaction(tx, true);
                }
                return true;
            }
            int tx_id = program.startTransaction("Renaming Function");
            try {
                temp.setName(name, SourceType.IMPORTED);
            } catch (DuplicateNameException e) {
                Symbol[] ss = program.getSymbolTable().getSymbols(addr);
                for (Symbol s : ss) {
                    if (s.getName().equals(name))
                        program.getSymbolTable().removeSymbolSpecial(s);
                }
                temp.setName(name, SourceType.IMPORTED);
            }
            program.endTransaction(tx_id, true);
            return true;
        }
        // No function at address, and failed to create one
        return false;
    }

    /** Every name this module's named-export table lists: the linker's own record. */
    private final java.util.Set<String> exportedNames = new java.util.HashSet<>();

    void applyExportedNames() throws Exception {
        int off = ThreeDSUtils.getInt(crxBytes, 0xD0);
        int num = ThreeDSUtils.getInt(crxBytes, 0xD4);
        if (num == 0) return;
        for (int i=0; i<num; i++) {
            String name = ThreeDSUtils.getName(crxBytes, getInt(crxBytes, off + (8L * i)));
            exportedNames.add(name);
            SegmentOffset segOff = new SegmentOffset(crxBytes, off + 4L + (8L * i));
            applyNameHere(name, segOff, program);
        }
    }

    void modifyIndexedExports() throws Exception {
        int off = ThreeDSUtils.getInt(crxBytes, 0xD8);
        int num = ThreeDSUtils.getInt(crxBytes, 0xDC);
        for (int i=0; i<num; i++) {
            SegmentOffset segOff = new SegmentOffset(crxBytes, off + (4L * i));
            String name = getOrCreateNameHere(segOff);
            if (!name.contains("public")) {
                applyNameHere("public_" + name, segOff, program);
            }
        }
    }

    void applyRelocs(Program here, CRXLibrary module,
                     List<RelocationEntry> relocs,
                     String symbol, Address exportFrom) throws Exception {
        Library moduleLibrary = libraries.get(module.name);
        int tx_id = program.startTransaction("Creating Data Labels");
        try {
            for (RelocationEntry patch : relocs) {
                Address importTo = patch.off.getAddr(segments);
                // A patch site in code is a PLT literal (or an instruction), never a function
                // entry, and naming it made one there: a function on the literal word, whose
                // later removal cleared the code unit and the import reference with it --
                // 30 PLT entries (MiniGame0 0x4a0, Kappei 0x5c8) lost their import record
                // that way. Data sites (vtable slots, typeinfo words) keep their label.
                SegmentOffset site = toSegmentOffset(importTo, segments);
                if (site != null && site.getIndex() != SegmentOffset.ID.TEXT) {
                    applyNameHere(symbol, site, here);
                }
//                ThreeDSUtils.labelNamedData(symbol, importTo, here);
                RefType relocType = switch (patch.type) {
                    case R_ARM_NONE -> null;
                    case R_ARM_TARGET1, R_ARM_ABS32, R_ARM_REL32, R_ARM_PREL31 -> RefType.DATA;
                    case R_ARM_THM_PC22, R_ARM_CALL -> RefType.UNCONDITIONAL_CALL;
                    case R_ARM_JUMP24 -> RefType.CONDITIONAL_JUMP;
                };
                rman.addExternalReference(
                        importTo,
                        moduleLibrary,
                        symbol,
                        exportFrom,
                        SourceType.IMPORTED,
                        0,
                        relocType
                );
            }
        } catch (Exception e) {
            program.endTransaction(tx_id, false);
            throw new Exception(String.format("Either %s or %s were closed (likely %s)",
                    this.name,module.name,module.name));
        }
        program.endTransaction(tx_id, true);
    }

    /**
     * This module's named export of {@code name}, read straight from its export table so it
     * works whether or not this module has been linked yet. Null when it exports no such name.
     */
    SegmentOffset findNamedExport(String name) {
        int off = ThreeDSUtils.getInt(crxBytes, 0xD0);
        int num = ThreeDSUtils.getInt(crxBytes, 0xD4);
        for (int i = 0; i < num; i++) {
            if (name.equals(ThreeDSUtils.getName(crxBytes, getInt(crxBytes, off + (8L * i))))) {
                return new SegmentOffset(crxBytes, off + 4L + (8L * i));
            }
        }
        return null;
    }

    /**
     * Imports by symbol name (header 0x100/0x104): { name offset, patch list offset }. The
     * module is not given -- the loader finds whichever one exports the name. Unbound, these
     * left every stub calling __aeabi_atexit with no import record, so 27 PLT entries across
     * the CROs could be named only for their address.
     */
    void applyNamedImports(List<CRXLibrary> crxLibraries) throws Exception {
        int off = ThreeDSUtils.getInt(crxBytes, 0x100);
        int num = ThreeDSUtils.getInt(crxBytes, 0x104);
        for (int i = 0; i < num; i++) {
            String name = ThreeDSUtils.getName(crxBytes, getInt(crxBytes, off + (8L * i)));
            int relocsOff = ThreeDSUtils.getInt(crxBytes, off + 4 + (8L * i));
            CRXLibrary exporter = null;
            SegmentOffset where = null;
            for (CRXLibrary l : crxLibraries) {
                if (l == this || l.crxBytes == null) continue;
                where = l.findNamedExport(name);
                if (where != null) { exporter = l; break; }
            }
            if (exporter == null) {
                Msg.warn(this, String.format("%s: named import %s has no exporter among the " +
                        "linked modules; left unbound", this.name, name));
                continue;
            }
            // A module reached only by name has no entry in the import module table, so
            // importModules never registered it. MLDT's CROs import everything this way --
            // their module table is empty -- and every import was dropped here.
            if (!libraries.containsKey(exporter.name)) {
                addLibrary(exporter);
            }
            applyRelocs(program, exporter, getRelocs(crxBytes, relocsOff), name,
                    where.getAddr(exporter.segments));
        }
    }

    void applyImports(List<CRXLibrary> crxLibraries) throws Exception {
        applyNamedImports(crxLibraries);
        int off = ThreeDSUtils.getInt(crxBytes, 0xF0);
        int num = ThreeDSUtils.getInt(crxBytes, 0xF4);
        for (int i=0; i<num; i++) {
            long step_i = 0x14L * i;
            String crxName = getName(crxBytes, ThreeDSUtils.getInt(crxBytes,off + step_i));
            int indexedOff = ThreeDSUtils.getInt(crxBytes, off + 0x4 + step_i);
            int indexedNum = ThreeDSUtils.getInt(crxBytes, off + 0x8 + step_i);
            int anonOff = ThreeDSUtils.getInt(crxBytes, off + 0xC + step_i);
            int anonNum = ThreeDSUtils.getInt(crxBytes, off + 0x10 + step_i);
            for (int j=0; j<indexedNum; j++) {
                int relocsOff = ThreeDSUtils.getInt(crxBytes, indexedOff + 0x4 + (0x8L * j));
                ThreeDSUtils.getRelocs(crxBytes, relocsOff);
                // TODO: Import indexed
            }
            CRXLibrary module = crxLibraries.stream()
                    .filter(l -> l.name.equalsIgnoreCase(crxName))
                    .findFirst().orElse(null);
            for (int j=0; j<anonNum; j++) {
                SegmentOffset symbolOffset = new SegmentOffset(crxBytes, anonOff + 0x8L * j);
                int relocsOff = ThreeDSUtils.getInt(crxBytes, anonOff + 0x4 + (0x8L * j));
                if (module == null) {
                    throw new NullPointerException(
                            String.format("Library %s was not found in the library list!\n", crxName));
                }
                List<RelocationEntry> relocs = getRelocs(crxBytes, relocsOff);
                Address symbolAddress = symbolOffset.getAddr(module.segments);
                String symbolToImport = module.getOrCreateNameHere(symbolOffset);
                if (symbolToImport == null) {
                    symbolToImport = String.format("UNK_%s",symbolAddress);
                }
                applyRelocs(program, module, relocs,
                        symbolToImport, symbolAddress);
            }
        }
    }

    void applyExitLoadUnresolved() throws Exception {
        SegmentOffset onLoad = new SegmentOffset(crxBytes, 0xA4);
        applyNameHere("OnLoad", onLoad);
        SegmentOffset onExit = new SegmentOffset(crxBytes, 0xA8);
        applyNameHere("OnExit", onExit);
        SegmentOffset onUnresolved = new SegmentOffset(crxBytes, 0xAC);
        applyNameHere("OnUnresolved", onUnresolved);
    }

    public void importModules(List<CRXLibrary> crxLibraries) throws Exception {
        int tx_id = program.startTransaction("Importing Module");
        try {
            var exman = program.getExternalManager();
            for (String libName : exman.getExternalLibraryNames()) {
                exman.removeExternalLibrary(libName);
            }
            int off = getInt(crxBytes, 0xF0);
            int num = getInt(crxBytes, 0xF4);
            for (int i = 0; i < num; i++) {
                long step_i = 0x14L * i;
                String crxName = getName(crxBytes, getInt(crxBytes, off + step_i));
                CRXLibrary module = crxLibraries.stream()
                        .filter(l -> l.name.equalsIgnoreCase(crxName))
                        .findFirst().orElse(null);
                if (module == null) {
                    throw new Exception(String.format("Library %s did not exist in the provided directory!", crxName));
                }
                registerLibrary(module);
            }
        } catch (Exception e) {
            program.endTransaction(tx_id, false);
            throw e;
        }
        program.endTransaction(tx_id, true);
    }

    /** Registers {@code module} as an external library of this program, in its own transaction. */
    private void addLibrary(CRXLibrary module) throws Exception {
        int tx_id = program.startTransaction("Importing Module");
        try {
            registerLibrary(module);
        } catch (Exception e) {
            program.endTransaction(tx_id, false);
            throw e;
        }
        program.endTransaction(tx_id, true);
    }

    private void registerLibrary(CRXLibrary module) throws Exception {
        var exman = program.getExternalManager();
        Library moduleLibrary = exman.addExternalLibraryName(module.name, SourceType.IMPORTED);
        libraries.put(module.name, moduleLibrary);
        exman.setExternalPath(module.name, module.file.getPathname(), true);
    }

    public void link(List<CRXLibrary> crxLibraries) throws Exception {
        applyExitLoadUnresolved();

        applyExportedNames();
        modifyIndexedExports();

        applyImports(crxLibraries);

        demangleAll();
    }
}
