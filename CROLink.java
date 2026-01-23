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
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import util.*;

import static util.ThreeDSUtils.*;

public class CROLink extends GhidraScript {

    private final List<CRXLibrary> crxLibraries = new ArrayList<>();

    @Override
    protected void run() throws Exception {
        // This script will link all cro's and the crs together.

        // Get pertinent files, and form .crx into proper CRXLibrary objects
        DomainFile codeFile = askDomainFile("Select the static module (code.bin / .code)");
        File crsFile = askFile("Select static.crs","OK");
        DomainFolder croFolder = askProjectFolder("Select the cro directory");
        ProgramManager pman = getState().getTool().getService(ProgramManager.class);
        crxLibraries.add(new CRXLibrary(codeFile, crsFile, pman, monitor));
        for (DomainFile cro : croFolder.getFiles()) {
            crxLibraries.add(new CRXLibrary(cro, pman, monitor));
        }

        // Iterate through the list, linking each module to its imports
        for (CRXLibrary crx : crxLibraries) crx.link(crxLibraries);

        // All modules have been linked!
        printf("%d modules linked successfully!\n", crxLibraries.size());
    }
}

class CRXLibrary {

    private boolean isStatic = false;
    SegmentBlock[] segments;
    byte[] crxBytes;
    String name;
    private final ProgramManager pman;
    private final ReferenceManager rman;
    private final TaskMonitor monitor;

    // DO NOT get bytes from this file and expect
    //  to get crx information
    private final DomainFile file;

    // Assume this is always uninitialized at function start
    private Program program;

    Program startUsingProgram() {
        program = pman.openCachedProgram(file, this);
        return program;
    }

    void stopUsingProgram() {
        program.release(this);
    }

    private int tx_id;
    void startTransactingProgram(String task) {
        tx_id = program.startTransaction(task);
    }

    void stopTransactingProgram(boolean commit) {
        program.endTransaction(tx_id, commit);
    }

    /**
     * Contains the Library corresponding to the respective
     *   program('s external manager) in the CRXLibrary
     */
    private final HashMap<CRXLibrary, Library> libraries = new HashMap<>();

    int hash() {
        return Objects.hash(name);
    }

    CRXLibrary(DomainFile codeFile, File crsFile,
               ProgramManager pman, TaskMonitor monitor) throws Exception {
        isStatic = true;
        file = codeFile;
        name = "|static|";
        this.pman = pman;
        this.monitor = monitor;
        startUsingProgram();
            crxBytes = ThreeDSUtils.getAllBytes(crsFile);
            segments = ThreeDSUtils.readSegments(crxBytes, program);
            rman = program.getReferenceManager();
        stopUsingProgram();
    }

    CRXLibrary(DomainFile croFile,
               ProgramManager pman, TaskMonitor monitor) throws Exception {
        file = croFile;
        name = croFile.getName().split("\\.cro")[0];
        this.pman = pman;
        this.monitor = monitor;
        startUsingProgram();
            crxBytes = ThreeDSUtils.getAllBytes(program);
            segments = ThreeDSUtils.readSegments(crxBytes, program);
            rman = program.getReferenceManager();
        stopUsingProgram();
    }

    boolean disassemble(Address addr, boolean thumb) {
        var adc = new ArmDisassembleCommand(addr, null, thumb);
        startTransactingProgram(String.format("Disassembling %s...",file));
        try {
            adc.applyTo(program, monitor);
        } catch (Exception e) {
            stopTransactingProgram(false);
            throw e;
        }
        stopTransactingProgram(true);
        return (adc.getDisassembledAddressSet() != null);
    }

    // Demangle names
    void demangleAll() throws Exception {
        startUsingProgram();
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
        stopUsingProgram();
    }

    public String getOrCreateNameHere(SegmentOffset segOff) throws Exception {
        Address addr = segOff.getAddr(segments);
        String name = null;
        startUsingProgram();
            Symbol[] symbols = program.getSymbolTable().getSymbols(addr);
            if (symbols.length == 0) {
                // No symbol. Need to create one
                if (segOff.getIndex() == SegmentOffset.ID.TEXT) {
                    // Create function, get name
                    Function func = program.getListing()
                            .createFunction(null, addr, null, SourceType.IMPORTED);
                    name = func.getName();
                } else {
                    // Create global var
                    name = "DAT_" + addr;
                    Symbol symbol = program.getSymbolTable()
                            .createLabel(addr, name, SourceType.IMPORTED);
                    name = symbol.getName();
                }
            } else {
                name = symbols[0].getName();
            }
        stopUsingProgram();
        return name;
    }

    boolean applyNameHere(String name, SegmentOffset segOff,
                          Program program) throws Exception {
        Address addr = segOff.getAddr(segments);
        if (addr == null) return false;

        if (segOff.getIndex() == SegmentOffset.ID.TEXT) {
            return applyFunctionName(name, addr, program);
        } else {
            Symbol check = ThreeDSUtils.labelNamedData(name, addr, program);
            return check != null;
        }
    }

    boolean applyNameHere(String name, SegmentOffset segOff) throws Exception {
        startUsingProgram();
            boolean retVal = applyNameHere(name, segOff, program);
        stopUsingProgram();
        return retVal;
    }

    boolean applyNameThere(String name, SegmentOffset segOff,
                           CRXLibrary crxLibrary) throws Exception {
        return crxLibrary.applyNameHere(name, segOff);
    }

    boolean applyFunctionName(String name, Address addr,
                              Program program) throws Exception {
        boolean thumb = (addr.getOffset() & 0x1) == 1;
        if (thumb) addr = addr.subtract(1);
        Function temp = program.getListing().getFunctionAt(addr);
        // If not a function entrypoint, can we make it one?
        if (temp == null) {
            program.getListing().createFunction(
                    name, addr, null, SourceType.IMPORTED);
            temp = program.getListing().getFunctionAt(addr);
        }

        if (temp != null) {
            temp.setName(name, SourceType.IMPORTED);
            return true;
        }
        // No function at address, and failed to create one
        return false;
    }

    void applyExportedNames() throws Exception {
        startUsingProgram();
            int off = ThreeDSUtils.getInt(crxBytes, 0xD0);
            int num = ThreeDSUtils.getInt(crxBytes, 0xD4);
            for (int i=0; i<num; i++) {
                String name = ThreeDSUtils.getName(crxBytes, off + (8L * i));
                SegmentOffset segOff = new SegmentOffset(crxBytes, off + 4L + (8L * i));
                applyNameHere(name, segOff, program);
            }
        stopUsingProgram();
    }

    void modifyIndexedExports() throws Exception {
        startUsingProgram();
            int off = ThreeDSUtils.getInt(crxBytes, 0xD8);
            int num = ThreeDSUtils.getInt(crxBytes, 0xDC);
            for (int i=0; i<num; i++) {
                SegmentOffset segOff = new SegmentOffset(crxBytes, off + (4L * i));
                String name = getOrCreateNameHere(segOff);
                if (!name.contains("public")) {
                    applyNameHere("public_" + name, segOff, program);
                }
            }
        stopUsingProgram();
    }

    void applyRelocs(Program here, CRXLibrary module,
                     List<RelocationEntry> relocs,
                     String symbol, Address exportFrom) throws Exception {
        module.startUsingProgram();
        Library moduleLibrary = module.libraries.computeIfAbsent(this, m -> {
            try {
                return m.program.getExternalManager()
                        .addExternalLibraryName(m.name, SourceType.IMPORTED);
            } catch (Exception e) {
                return null;
            }
        });
        for (RelocationEntry patch : relocs) {
            Address importTo = patch.off.getAddr(module.segments);
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
        module.stopUsingProgram();
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
            for (int j=0; j<anonNum; j++) {
                SegmentOffset symbolOffset = new SegmentOffset(crxBytes, anonOff + 0x8L * j);
                int relocsOff = ThreeDSUtils.getInt(crxBytes, anonOff + 0x4 + (0x8L * j));
                CRXLibrary module = crxLibraries.stream()
                        .filter(l -> l.name.equalsIgnoreCase(crxName))
                        .findFirst().orElse(null);
                if (module == null) {
                    throw new NullPointerException(
                            String.format("Library %s was not found in the library list!\n", crxName));
                }
                List<RelocationEntry> relocs = getRelocs(crxBytes, relocsOff);
                String symbolToImport = module.getOrCreateNameHere(symbolOffset);
                Address symbolAddress = symbolOffset.getAddr(module.segments);
                startUsingProgram();
                    applyRelocs(program, module, relocs,
                            String.format("%s_%s", module.name, symbolToImport),
                            symbolAddress);
                stopUsingProgram();
            }
        }
    }

    void link(List<CRXLibrary> crxLibraries) throws Exception {
        applyExportedNames();
        modifyIndexedExports();
        demangleAll();

        applyImports(crxLibraries);
    }
}