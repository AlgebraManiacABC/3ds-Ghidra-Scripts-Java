// Links ALL .cro modules with themselves, and with the static binary (using .crs)
// @category 3DS

import java.io.*;
import java.net.URL;
import java.util.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.script.GhidraState;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.demangler.*;
import ghidra.framework.model.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import util.CROLibrary;
import util.SegmentBlock;
import util.SegmentOffset;
import util.ThreeDSUtils;

import static util.ThreeDSUtils.labelNamedData;

public class CROLink extends GhidraScript {

    private final List<CRXLibrary> crxLibraries = new ArrayList<>();

    @Override
    protected void run() throws Exception {
        // This script will link all cro's and the crs together.

        // Make a list/array of crx, with index 0 as the |static| module
        DomainFile codeFile = askDomainFile("Select the static module (code.bin / .code)");
        File crsFile = askFile("Select static.crs","OK");
        DomainFolder croFolder = askProjectFolder("Select the cro directory");
        ProgramManager pman = getState().getTool().getService(ProgramManager.class);
//        crxLibraries.add(new CRXLibrary(codeFile, crsFile, pman));
//        for (DomainFile cro : croFolder.getFiles()) {
//            crxLibraries.add(new CRXLibrary(cro, pman));
//        }

        // Iterate through the list, linking i with i+j for i = 0..n and for j = i..n
        // Once iteration completes, all modules have been linked!
    }
}

class CRXLibrary {
    SegmentBlock[] segments;
    byte[] crxBytes;
//    private GhidraScript script;
    private final ProgramManager pman;
    private final TaskMonitor monitor;

    // DO NOT get bytes from this file and expect
    //  to get crx information
    private final DomainFile file;

    // Assume this is always uninitialized
    private Program program;

    void startUsingProgram() {
        program = pman.openCachedProgram(file, this);
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

    CRXLibrary(DomainFile codeFile, File crsFile,
               ProgramManager pman, TaskMonitor monitor) throws Exception {
        file = codeFile;
        this.pman = pman;
        this.monitor = monitor;
        startUsingProgram();
            crxBytes = ThreeDSUtils.getAllBytes(crsFile);
            segments = ThreeDSUtils.readSegments(crxBytes, program);
        stopUsingProgram();
    }

    CRXLibrary(DomainFile croFile,
               ProgramManager pman, TaskMonitor monitor) throws Exception {
        file = croFile;
        this.pman = pman;
        this.monitor = monitor;
        startUsingProgram();
            crxBytes = ThreeDSUtils.getAllBytes(program);
            segments = ThreeDSUtils.readSegments(crxBytes, program);
        stopUsingProgram();
    }

    boolean disassemble(Address addr, boolean thumb) {
        ArmDisassembleCommand adc = new ArmDisassembleCommand(addr, null, thumb);
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

    boolean applyFunctionName(String name, Address addr,
                              Program program) throws Exception {
        boolean thumb = (addr.getOffset() & 0x1) == 1;
        if (thumb) addr = addr.subtract(1);
        Function temp = program.getListing().getFunctionAt(addr);
        // If not a function entrypoint, can we make it one?
        if (temp == null) {
            CreateFunctionCmd cfc = new CreateFunctionCmd(name, addr, null, SourceType.IMPORTED);
            startTransactingProgram("Creating function...");
            try {
                cfc.applyTo(program, monitor);
            } catch (Exception e) {
                stopTransactingProgram(false);
                throw e;
            }
            stopTransactingProgram(true);
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

    void link() {

    }
}