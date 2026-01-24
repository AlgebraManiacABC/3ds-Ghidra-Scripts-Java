// Links ALL .cro modules with themselves, and with the static binary (using .crs)
// @category 3DS

import java.io.*;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.demangler.*;
import ghidra.framework.model.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import util.*;

import static util.ThreeDSUtils.*;

public class CROLink extends GhidraScript {

    private final List<CRXLibrary> crxLibraries = new ArrayList<>();

    @Override
    protected void run() throws Exception {
        // This script will link all .cro files and the static.crs file together.

        // Get pertinent files, and form .crx into proper CRXLibrary objects
        DomainFile codeFile = askDomainFile("Select the static module (code.bin / .code)");
        File crsFile = askFile("Select static.crs","OK");
        DomainFolder croFolder = askProjectFolder("Select the cro directory");
        ProgramManager pman = getState().getTool().getService(ProgramManager.class);
        crxLibraries.add(new CRXLibrary(codeFile, crsFile, pman, monitor));
        for (DomainFile cro : croFolder.getFiles()) {
            if (cro.getName().contains(".cro")) {
                crxLibraries.add(new CRXLibrary(cro, pman, monitor));
            }
        }

        for (CRXLibrary crx : crxLibraries) {
            crx.importModules(crxLibraries);
        }
        // Iterate through the list, linking each module to its imports
        for (CRXLibrary crx : crxLibraries) {
            crx.link(crxLibraries);
        }
        // Release hold of the programs
        for (CRXLibrary crx : crxLibraries) {
            crx.cleanup();
        }

        // All modules have been linked!
        printf("%d modules linked successfully!\n", crxLibraries.size());
    }
}

class CRXLibrary {

    SegmentBlock[] segments;
    byte[] crxBytes;
    String name;
    private final ReferenceManager rman;
    private final TaskMonitor monitor;

    // DO NOT get bytes from this file and expect
    //  to get crx information
    private final DomainFile file;

    Program program;

    /**
     * Contains the Library corresponding to the respective
     *   program('s external manager) in the CRXLibrary
     */
    private final HashMap<String, Library> libraries = new HashMap<>();

    CRXLibrary(DomainFile codeFile, File crsFile,
               ProgramManager pman, TaskMonitor monitor) throws Exception {
        file = codeFile;
        name = "|static|";
        this.program = pman.openCachedProgram(codeFile, this);
        this.monitor = monitor;
        crxBytes = ThreeDSUtils.getAllBytes(crsFile);
        segments = ThreeDSUtils.readSegments(crxBytes, program);
        rman = program.getReferenceManager();
    }

    CRXLibrary(DomainFile croFile,
               ProgramManager pman, TaskMonitor monitor) throws Exception {
        file = croFile;
        name = croFile.getName().split("\\.cro")[0];
        this.program = pman.openCachedProgram(croFile, this);
        this.monitor = monitor;
        crxBytes = ThreeDSUtils.getAllBytes(program);
        segments = ThreeDSUtils.readSegments(crxBytes, program);
        rman = program.getReferenceManager();
    }

    void cleanup() {
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
            for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
                String name = symbol.getName();
                Address addr = symbol.getAddress();
                List<DemangledObject> demangledObjects = DemanglerUtil.demangle(program, name, addr);
                if (!demangledObjects.isEmpty()) {
                    demangledObjects.getFirst().applyTo(program, addr, new DemanglerOptions(), monitor);
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
            Symbol check = ThreeDSUtils.labelNamedData(name, addr, program);
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
                ThreeDSUtils.labelNamedData(symbol, importTo, here);
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
                        String.format("%s_%s", module.name, symbolToImport),
                        symbolAddress);
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

    void importModules(List<CRXLibrary> crxLibraries) throws Exception {
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

    void link(List<CRXLibrary> crxLibraries) throws Exception {
        applyExitLoadUnresolved();

        applyExportedNames();
        modifyIndexedExports();
        demangleAll();

        applyImports(crxLibraries);
    }
}