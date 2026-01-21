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
import ghidra.app.services.ProgramManager;
import ghidra.app.util.demangler.*;
import ghidra.framework.model.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;

public class CROLink extends GhidraScript {

    @Override
    protected void run() throws Exception {
        // This script will link all cro's and the crs together.

        // Make a list/array of crx, with index 0 as the |static| module
        DomainFile codeFile = askDomainFile("Select the static module (code.bin / .code)");
        DomainFile crsFile = askDomainFile("Select static.crs");
        DomainFolder croFolder = askProjectFolder("Select the cro directory");

        // Iterate through the list, linking i with i+j for i = 0..n and for j = i..n
        // Once iteration completes, all modules have been linked!
    }

    // Need a linking method which accepts two crx
    // Need(?) a specialized crs linker which accepts .code, .crs, .cro
}