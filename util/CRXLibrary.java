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
        } else {
            file = codeFile;
            name = "|static|";
            program = pman.openCachedProgram(codeFile, this);
            this.monitor = monitor;
            segments = ThreeDSUtils.readSegments(crxBytes, program);
            rman = program.getReferenceManager();
        }
    }

    public CRXLibrary(DomainFile croFile,
               ProgramManager pman, TaskMonitor monitor) throws Exception {
        program = pman.openCachedProgram(croFile, this);
        crxBytes = ThreeDSUtils.getAllBytes(program);
        if (!isValidCRO0()) {
            file = null;
            name = null;
            program.release(this);
            program = null;
            this.monitor = null;
            segments = null;
            rman = null;
        } else {
            file = croFile;
            name = croFile.getName().split("\\.cro")[0];
            this.monitor = monitor;
            segments = ThreeDSUtils.readSegments(crxBytes, program);
            rman = program.getReferenceManager();
        }
    }

    public void cleanup(boolean save) throws Exception {
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
        if (save)
            program.save("CROLink save", monitor);
        program.release(this);
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
            for (Symbol mangled : program.getSymbolTable().getAllSymbols(true)) {
                Address addr = mangled.getAddress();
                List<DemangledObject> objs = DemanglerUtil.demangle(program, mangled.getName(), addr);
                for (var obj : objs) {
                    boolean applied = false;
                    try {
                        applied = obj.applyTo(
                                program, addr, new DemanglerOptions(), monitor);
                    } catch (IllegalArgumentException e) {
                        Msg.error(this,String.format("Couldn't apply obj '%s' to addr %s",
                                addr, obj));
                        continue;
                    }
                    if (applied) {
                        program.getSymbolTable().removeSymbolSpecial(mangled);
                        Function func = program.getFunctionManager().getFunctionAt(addr);
                        if (func != null) {
                            func.setName(obj.getName(), SourceType.IMPORTED);
                            if (obj.getNamespace() != null) {
                                Namespace ns = NamespaceUtils.createNamespaceHierarchy(
                                        obj.getNamespace().toString(),
                                        null,  // global
                                        program,
                                        SourceType.IMPORTED
                                );
                                func.setParentNamespace(ns);
                            }
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

    public String getOrCreateNameHere(SegmentOffset segOff) throws Exception {
        Address addr = segOff.getAddr(segments);
        String name;
        Symbol[] symbols = program.getSymbolTable().getSymbols(addr);
        if (symbols.length == 0) {
            // No symbol. Need to create one
            if (segOff.getIndex() == SegmentOffset.ID.TEXT) {
                Function func = program.getListing().getFunctionAt(addr);
                if (func != null) return func.getName();
                // Disassemble first, if needed
                boolean disassembled = program.getListing().getInstructionAt(addr) != null;
                if (!disassembled) {
                    disassemble(addr, (addr.getOffset() & 0x1) == 1);
                }
                // Create function, get name
                createFunctionHere(null, addr);
                func = program.getListing().getFunctionAt(addr);
                if (func == null) {
                    return String.format("INVALID_%s_%s",this.name,segOff);
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
            name = symbols[0].getName();
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
            Symbol check = null;
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
            createFunctionHere(name, addr);
            temp = program.getListing().getFunctionAt(addr);
        }

        if (temp != null) {
            if (temp.getName().equals(name)) return true;
            int tx_id = program.startTransaction("Renaming Function");
            try {
                temp.setName(name, SourceType.IMPORTED);
            } catch (DuplicateNameException e) {
                Symbol[] ss = program.getSymbolTable().getSymbols(addr);
                for (Symbol s : ss) program.getSymbolTable().removeSymbolSpecial(s);
                temp.setName(name, SourceType.IMPORTED);
            }
            program.endTransaction(tx_id, true);
            return true;
        }
        // No function at address, and failed to create one
        return false;
    }

    void applyExportedNames() throws Exception {
        int off = ThreeDSUtils.getInt(crxBytes, 0xD0);
        int num = ThreeDSUtils.getInt(crxBytes, 0xD4);
        if (num == 0) return;
        for (int i=0; i<num; i++) {
            String name = ThreeDSUtils.getName(crxBytes, getInt(crxBytes, off + (8L * i)));
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
                applyNameHere(symbol, toSegmentOffset(importTo,segments), here);
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

    void applyImports(List<CRXLibrary> crxLibraries) throws Exception {
        // TODO: Import named
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
                Library moduleLibrary = exman.addExternalLibraryName(module.name, SourceType.IMPORTED);
                libraries.put(module.name, moduleLibrary);
                exman.setExternalPath(module.name, module.file.getPathname(), true);
            }
        } catch (Exception e) {
            program.endTransaction(tx_id, false);
            throw e;
        }
        program.endTransaction(tx_id, true);
    }

    public void link(List<CRXLibrary> crxLibraries) throws Exception {
        applyExitLoadUnresolved();

        applyExportedNames();
        modifyIndexedExports();

        applyImports(crxLibraries);

        demangleAll();
    }
}
