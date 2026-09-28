//
//
//@category 3DS

import java.nio.charset.StandardCharsets;
import java.util.*;

import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import util.ThreeDSUtils;

public class LabelServiceHandles extends GhidraScript {

    Map<Address, Set<String>> service_refs = new HashMap<>();
    DecompInterface decompInterface = null;

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            popup("This script requires that a program be open in the tool");
            return;
        }

        // Verify that nn::svc::ConnectToPort exists and is named
        Namespace nn_svc = NamespaceUtils.createNamespaceHierarchy(
                "nn::svc",
                currentProgram.getGlobalNamespace(),
                currentProgram,
                SourceType.USER_DEFINED);
        var iter = getSymbols("ConnectToPort",nn_svc);
        if (iter.isEmpty()) throw new Exception("Couldn't find nn::svc::ConnectToPort (swi 0x2D)! Please find and label as such.");
        if (iter.size() > 1) throw new Exception("More than 1 nn::svc::ConnectToPort defined! Single out the main one (swi 0x2D).");
        Symbol portHandle = iter.getFirst();
        var refs = getReferencesTo(portHandle.getAddress());

        collectServiceReferences();
        setupDecompiler();
        printf("Examining all references to nn::svc::ConnectToPort...\n");
        for (Reference ref : refs) {
            Address addr = ref.getFromAddress();
            var args = getCallArgsFromRef(ref);
            if (args == null) {
                printf("Couldn't get args for %s!\n",addr);
                continue;
            }
            if (args.length < 3) {
                printf("Too few arguments at %s\n",addr);
                continue;
            }
            var handleRef = args[1];
//            var service = args[2];
            if (!handleRef.isAddress()) {
                printf("Unable to detect service handle name at %s\n",addr);
                continue;
            }
            Address handle = toAddr(currentProgram
                    .getMemory().getInt(handleRef.getAddress()));
            Function caller = getFunctionContaining(handle);
            if (caller == null) {
                printf("Unknown function referencing a service at %s\n",addr);
                continue;
            }
            Address entrypoint = caller.getEntryPoint();
            Set<String> services = service_refs.getOrDefault(entrypoint, null);
            if (services == null || services.isEmpty()) continue;
            for (String svcName : services) {
//                createLabel(handle, svcName, nn_svc, true, SourceType.IMPORTED);
                printf("Would create label %s at %s\n",svcName,handle);
            }
        }
    }

    void setupDecompiler() {
        decompInterface = new DecompInterface();
        decompInterface.openProgram(currentProgram);
    }

    Varnode[] getCallArgs(Function func, Address to) {
        DecompileResults decompiledFunc = null;
        try {
            decompiledFunc = decompInterface.decompileFunction(func, 60, monitor);
        } catch (Exception e) {
            printf("Exception trying to decompile %s with %s\n",func,decompInterface);
            throw e;
        }
        if (decompiledFunc == null || decompiledFunc.getHighFunction() == null) {
            printf("Couldn't decompile %s!\n",func);
            return null;
        }
        var opIter = decompiledFunc.getHighFunction().getPcodeOps();
        printf("Currently examining %s:\n",func);

        while (opIter.hasNext()) {
            var op = opIter.next();
            printf("\t%s\n",op);
            if (op.getMnemonic().equals("CALL")) {
                var inputs = op.getInputs();
                printf("\t\t^-- CALL! Inputs: %s\n", Arrays.toString(inputs));
                if (inputs == null) continue;
                if (inputs[0].getAddress().equals(to)) {
                    return inputs;
                } else {
                    printf("\t\tinput %s did not contain %s\n",inputs[0],to);
                }
            }
        }
        return null;
    }

    Varnode[] getCallArgsFromRef(Reference callRef) {
        Address from = callRef.getFromAddress();
        Address to = callRef.getToAddress();
        printf("Getting Call Args %s\n",callRef);
        Function func = getFunctionContaining(from);
        if (func == null) {
            boolean disassembled = currentProgram.getListing().getInstructionAt(from) != null;
            if (!disassembled) {
                disassemble(from, (from.getOffset() & 0x1) == 1);
            }
            // Create function, get name
            var cfc = new CreateFunctionCmd("FUN_" + from, from, null, SourceType.IMPORTED);
            cfc.applyTo(currentProgram, monitor);
            func = currentProgram.getListing().getFunctionAt(from);
            if (func == null) {
                printf("Couldn't get function at %s\n",from);
                return null;
            }
        }
        return getCallArgs(func, to);
    }

    boolean disassemble(Address addr, boolean thumb) {
        var adc = new ArmDisassembleCommand(addr, null, thumb);
        adc.applyTo(currentProgram, monitor);
        return (adc.getDisassembledAddressSet() != null);
    }

    /**
     * Collects all references to known service strings (e.g., "cam:u", "fs:USER", etc.)
     * For each reference, gets the containing function, and makes its entry address
     *  the key to a Dictionary whose values are the service strings that function
     *  calls, as a set.
     */
    protected void collectServiceReferences() {
        Memory memory = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();
        for (String service : service_names) {
            // Find ALL references to this service
            Address maxAddr = currentProgram.getMaxAddress();
            for (Address addr = currentProgram.getMinAddress(); addr.compareTo(maxAddr) < 0; ) {
                addr = memory.findBytes(
                        addr.next(),
                        service.getBytes(StandardCharsets.UTF_8),
                        null, // no mask
                        true, // forward search
                        monitor
                );
                if (addr == null) break;

                // Skip cam:u when searching for am:u
                try {
                    if (service.equals("am:u") && memory.getByte(addr.add(1)) == 'c') continue;
                } catch (MemoryAccessException m) {
                    println("MemoryAccessException");
                }

                if (listing.getDataAt(addr) == null) {
                    // Found a string, but it isn't a DAT in Ghidra. Let's try to make one
                    try {
                        createAsciiString(addr);
                    } catch (Exception ignored) {}
                }

                // Add all references to dict
                Reference[] refs = getReferencesTo(addr);
                for (Reference ref : refs) {
                    Function caller = getFunctionContaining(ref.getFromAddress());
                    if (caller != null) {
                        service_refs.computeIfAbsent(
                                caller.getEntryPoint(),
                                k -> new HashSet<>()
                        ).add(service);
                    }
                }
            }
        }
    }

    static String colonToUnderscoreAndLower(String service) {
        return service.replace(':', '_').toLowerCase();
    }

    static final List<String> service_names = List.of(
        "fs:USER",
        "fs:LDR",
        "fs:REG",
        "ps:ps",
        "PxiFS0",
        "PxiFS1",
        "PxiFSB",
        "PxiFSR",
        "PxiPM",
        "pxi:am9",
        "pxi:dev",
        "pxi:mc",
        "pxi:ps9",
        "am:app",
        "am:net",
        "am:u",
        "am:sys",
        "am:pipe",
        "pm:app",
        "pm:dbg",
        "nim:aoc",
        "nim:ndm",
        "nim:s",
        "nim:u",
        "cfg:u",
        "cfg:s",
        "cfg:i",
        "cfg:nor",
        "ns:s",
        "ns:p",
        "ns:c",
        "APT:A",
        "APT:S",
        "APT:U",
        "ldr:ro",
        "ndm:u",
        "csnd:SND",
        "cam:u",
        "y2r:u",
        "cam:s",
        "cam:c",
        "cam:q",
        "cdc:HID",
        "cdc:MIC",
        "cdc:CSN",
        "cdc:DSP",
        "cdc:LGY",
        "cdc:CHK",
        "dlp:CLNT",
        "dlp:FKCL",
        "dlp:SRVR",
        "dsp::DSP",
        "gsp::Lcd",
        "gsp::Gpu",
        "boss:U",
        "boss:P",
        "boss:M",
        "cecd:u",
        "cecd:s",
        "cecd:ndm",
        "ir:u",
        "ir:USER",
        "ir:rst",
        "i2c::MCU",
        "i2c::CAM",
        "i2c::LCD",
        "i2c::DEB",
        "i2c::HID",
        "i2c::IR",
        "i2c::EEP",
        "i2c::NFC",
        "i2c::QTM",
        "gpio:CDC",
        "gpio:MCU",
        "gpio:HID",
        "gpio:NWM",
        "gpio:IR",
        "gpio:NFC",
        "gpio:QTM",
        "hid:NFC",
        "hid:QTM",
        "hid:SPVR",
        "hid:USER",
        "ptm:gets",
        "ptm:play",
        "ptm:s",
        "ptm:sets",
        "ptm:sysm",
        "ptm:u",
        "nwm::CEC",
        "nwm::EXT",
        "nwm::INF",
        "nwm::SAP",
        "nwm::SOC",
        "nwm::TST",
        "nwm::UDS",
        "http:C",
        "ssl:C",
        "soc:P",
        "soc:U",
        "ac:i",
        "ac:u",
        "frd:a",
        "frd:n",
        "frd:u",
        "news:s",
        "news:u",
        "pdn:s",
        "pdn:d",
        "pdn:i",
        "pdn:g",
        "pdn:c",
        "SPI::NOR",
        "SPI::CD2",
        "SPI::CS2",
        "SPI::CS3",
        "SPI::DEF",
        "Loader",
        "mcu::CAM",
        "mcu::GPU",
        "mcu::HID",
        "mcu::RTC",
        "mcu::SND",
        "mcu::NWM",
        "mcu::HWC",
        "mcu::PLS",
        "mcu::CDC",
        "mic:u",
        "act:a",
        "act:u",
        "mp:u",
        "nfc:dev",
        "nfc:m",
        "nfc:p",
        "nfc:r",
        "nfc:s",
        "nfc:u",
        "mvd:STD",
        "l2b:u",
        "l2b2:u",
        "y2r2:u",
        "qtm:u",
        "qtm:s",
        "qtm:sp",
        "qtm:c"
    );
}