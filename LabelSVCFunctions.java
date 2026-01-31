//
//
//@category 3DS

import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.*;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.model.listing.BookmarkType;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;

public class LabelSVCFunctions extends GhidraScript {

    static boolean isInitialized = false;
    static Map<Byte,String> ctr_svcs = new HashMap<Byte,String>();

    @Override
	protected void run() throws Exception {
        if (currentProgram == null) {
            popup("This script requires that a program be open in the tool");
            return;
        }

        if (!isInitialized) {
            doInitialize();
        }

        // Bytes corresponding to software_interrupt (swi)
        byte[] svc_bytes = {0x00, 0x00, 0x00, (byte)0xef};
        byte[] svc_mask = {0x00, (byte)0xff, (byte)0xff, (byte)0xff};
        Namespace nn_svc = NamespaceUtils.createNamespaceHierarchy(
                "nn::svc",
                currentProgram.getGlobalNamespace(),
                currentProgram,
                SourceType.USER_DEFINED);

        Listing listing = currentProgram.getListing();
        Address maxAddr = currentProgram.getMaxAddress();
        for (Address addr = currentProgram.getMinAddress(); addr.compareTo(maxAddr) < 0; ) {
            addr = currentProgram.getMemory().findBytes(
                addr.next(),
                svc_bytes,
                svc_mask,
                true, // forward search
                monitor
            );
            if (addr == null) break;
            CodeUnit svc_instruction = listing.getCodeUnitAt(addr);
            if (svc_instruction == null) continue;
            // Get operand for swi
            byte id = svc_instruction.getBytes()[0];
            // Get svc name
            String name = ctr_svcs.get(id);
            // Ignore finds in unanalyzed/uninitialized data
            if (name == null || svc_instruction.toString().charAt(0) == '?' ) continue;
            printf("SVC found at 0x%s: %s (%s)\n",addr.toString(),svc_instruction.toString(),name);
            switch (name) {
                case "GetSystemTick", "ClearEvent", "CloseHandle", "SignalEvent", "ExitProcess",
                        "SendSyncRequest", "WaitSynchronization1", "WaitSynchronizationN",
                        "SetThreadPriority", "ReleaseMutex" -> {}
                default -> {
                    Function svc_func = getFunctionContaining(addr);
                    if (svc_func != null) {
                        switch(svc_func.getSymbol().getSource()) {
                            case USER_DEFINED, IMPORTED -> svc_func.setParentNamespace(nn_svc);
                            case AI, ANALYSIS, DEFAULT -> {
                                svc_func.setName(name, SourceType.USER_DEFINED);
                                svc_func.setParentNamespace(nn_svc);
                            }
                        }
                    }
                }
            }
            // Change software_interrupt(id) to software_interrupt(name) in decompiler view
            currentProgram.getEquateTable().getEquate(name).addReference(addr, 0);
            // Bookmark
            createBookmark(addr, "SVC", name);
        }
    }

    void doInitialize() {
        ctr_svcs.put((byte)0x03, "ExitProcess");
        ctr_svcs.put((byte)0x01, "ControlMemory");
        ctr_svcs.put((byte)0x02, "QueryMemory");
        ctr_svcs.put((byte)0x04, "GetProcessAffinityMask");
        ctr_svcs.put((byte)0x05, "SetProcessAffinityMask");
        ctr_svcs.put((byte)0x06, "GetProcessIdealProcessor");
        ctr_svcs.put((byte)0x07, "SetProcessIdealProcessor");
        ctr_svcs.put((byte)0x08, "CreateThread");
        ctr_svcs.put((byte)0x09, "ExitThread");
        ctr_svcs.put((byte)0x0A, "SleepThread");
        ctr_svcs.put((byte)0x0B, "GetThreadPriority");
        ctr_svcs.put((byte)0x0C, "SetThreadPriority");
        ctr_svcs.put((byte)0x0D, "GetThreadAffinityMask");
        ctr_svcs.put((byte)0x0E, "SetThreadAffinityMask");
        ctr_svcs.put((byte)0x0F, "GetThreadIdealProcessor");
        ctr_svcs.put((byte)0x10, "SetThreadIdealProcessor");
        ctr_svcs.put((byte)0x11, "GetCurrentProcessorNumber");
        ctr_svcs.put((byte)0x12, "Run");
        ctr_svcs.put((byte)0x13, "CreateMutex");
        ctr_svcs.put((byte)0x14, "ReleaseMutex");
        ctr_svcs.put((byte)0x15, "CreateSemaphore");
        ctr_svcs.put((byte)0x16, "ReleaseSemaphore");
        ctr_svcs.put((byte)0x17, "CreateEvent");
        ctr_svcs.put((byte)0x18, "SignalEvent");
        ctr_svcs.put((byte)0x19, "ClearEvent");
        ctr_svcs.put((byte)0x1A, "CreateTimer");
        ctr_svcs.put((byte)0x1B, "SetTimer");
        ctr_svcs.put((byte)0x1C, "CancelTimer");
        ctr_svcs.put((byte)0x1D, "ClearTimer");
        ctr_svcs.put((byte)0x1E, "CreateMemoryBlock");
        ctr_svcs.put((byte)0x1F, "MapMemoryBlock");
        ctr_svcs.put((byte)0x20, "UnmapMemoryBlock");
        ctr_svcs.put((byte)0x21, "CreateAddressArbiter");
        ctr_svcs.put((byte)0x22, "ArbitrateAddress");
        ctr_svcs.put((byte)0x23, "CloseHandle");
        ctr_svcs.put((byte)0x24, "WaitSynchronization1");
        ctr_svcs.put((byte)0x25, "WaitSynchronizationN");
        ctr_svcs.put((byte)0x26, "SignalAndWait");
        ctr_svcs.put((byte)0x27, "DuplicateHandle");
        ctr_svcs.put((byte)0x28, "GetSystemTick");
        ctr_svcs.put((byte)0x29, "GetHandleInfo");
        ctr_svcs.put((byte)0x2A, "GetSystemInfo");
        ctr_svcs.put((byte)0x2B, "GetProcessInfo");
        ctr_svcs.put((byte)0x2C, "GetThreadInfo");
        ctr_svcs.put((byte)0x2D, "ConnectToPort");
        ctr_svcs.put((byte)0x2E, "SendSyncRequest1");
        ctr_svcs.put((byte)0x2F, "SendSyncRequest2");
        ctr_svcs.put((byte)0x30, "SendSyncRequest3");
        ctr_svcs.put((byte)0x31, "SendSyncRequest4");
        ctr_svcs.put((byte)0x32, "SendSyncRequest");
        ctr_svcs.put((byte)0x33, "OpenProcess");
        ctr_svcs.put((byte)0x34, "OpenThread");
        ctr_svcs.put((byte)0x35, "GetProcessId");
        ctr_svcs.put((byte)0x36, "GetProcessIdOfThread");
        ctr_svcs.put((byte)0x37, "GetThreadId");
        ctr_svcs.put((byte)0x38, "GetResourceLimit");
        ctr_svcs.put((byte)0x39, "GetResourceLimitLimitValues");
        ctr_svcs.put((byte)0x3A, "GetResourceLimitCurrentValues");
        ctr_svcs.put((byte)0x3B, "GetThreadContext");
        ctr_svcs.put((byte)0x3C, "Break");
        ctr_svcs.put((byte)0x3D, "OutputDebugString");
        ctr_svcs.put((byte)0x3E, "ControlPerformanceCounter");
        ctr_svcs.put((byte)0x47, "CreatePort");
        ctr_svcs.put((byte)0x48, "CreateSessionToPort");
        ctr_svcs.put((byte)0x49, "CreateSession");
        ctr_svcs.put((byte)0x4A, "AcceptSession");
        ctr_svcs.put((byte)0x4B, "ReplyAndReceive1");
        ctr_svcs.put((byte)0x4C, "ReplyAndReceive2");
        ctr_svcs.put((byte)0x4D, "ReplyAndReceive3");
        ctr_svcs.put((byte)0x4E, "ReplyAndReceive4");
        ctr_svcs.put((byte)0x4F, "ReplyAndReceive");
        ctr_svcs.put((byte)0x50, "BindInterrupt");
        ctr_svcs.put((byte)0x51, "UnbindInterrupt");
        ctr_svcs.put((byte)0x52, "InvalidateProcessDataCache");
        ctr_svcs.put((byte)0x53, "StoreProcessDataCache");
        ctr_svcs.put((byte)0x54, "FlushProcessDataCache");
        ctr_svcs.put((byte)0x55, "StartInterProcessDma");
        ctr_svcs.put((byte)0x56, "StopDma");
        ctr_svcs.put((byte)0x57, "GetDmaState");
        ctr_svcs.put((byte)0x58, "RestartDma");
        ctr_svcs.put((byte)0x59, "SetGpuProt");
        ctr_svcs.put((byte)0x5A, "SetWifiEnabled");
        ctr_svcs.put((byte)0x60, "DebugActiveProcess");
        ctr_svcs.put((byte)0x61, "BreakDebugProcess");
        ctr_svcs.put((byte)0x62, "TerminateDebugProcess");
        ctr_svcs.put((byte)0x63, "GetProcessDebugEvent");
        ctr_svcs.put((byte)0x64, "ContinueDebugEvent");
        ctr_svcs.put((byte)0x65, "GetProcessList");
        ctr_svcs.put((byte)0x66, "GetThreadList");
        ctr_svcs.put((byte)0x67, "GetDebugThreadContext");
        ctr_svcs.put((byte)0x68, "SetDebugThreadContext");
        ctr_svcs.put((byte)0x69, "QueryDebugProcessMemory");
        ctr_svcs.put((byte)0x6A, "ReadProcessMemory");
        ctr_svcs.put((byte)0x6B, "WriteProcessMemory");
        ctr_svcs.put((byte)0x6C, "SetHardwareBreakPoint");
        ctr_svcs.put((byte)0x6D, "GetDebugThreadParam");
        ctr_svcs.put((byte)0x70, "ControlProcessMemory");
        ctr_svcs.put((byte)0x71, "MapProcessMemory");
        ctr_svcs.put((byte)0x72, "UnmapProcessMemory");
        ctr_svcs.put((byte)0x73, "CreateCodeSet");
        ctr_svcs.put((byte)0x74, "RandomStub");
        ctr_svcs.put((byte)0x75, "CreateProcess");
        ctr_svcs.put((byte)0x76, "TerminateProcess");
        ctr_svcs.put((byte)0x77, "SetProcessResourceLimits");
        ctr_svcs.put((byte)0x78, "CreateResourceLimit");
        ctr_svcs.put((byte)0x79, "SetResourceLimitValues");
        ctr_svcs.put((byte)0x7A, "AddCodeSegment");
        ctr_svcs.put((byte)0x7B, "Backdoor");
        ctr_svcs.put((byte)0x7C, "KernelSetState");
        ctr_svcs.put((byte)0x7D, "QueryProcessMemory");
        ctr_svcs.put((byte)0xFF, "StopPoint");

        // Add these svc strings to the equate table
        EquateTable eqtab = currentProgram.getEquateTable();
        for (byte id : ctr_svcs.keySet()) {
            try {
                eqtab.createEquate(ctr_svcs.get(id), id);
            } catch (DuplicateNameException | InvalidInputException dne) {};
        }
        isInitialized = true;
    }
}