//
//
//@category 3DS

import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.listing.Function;
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
            Function svc_func = getFunctionAt(addr);
            if (svc_func != null) {
                svc_func.setName(name, SourceType.USER_DEFINED);
            }
            // Change software_interrupt(id) to software_interrupt(name) in decompiler view
            currentProgram.getEquateTable().getEquate(name).addReference(addr, 0);
            // Bookmark
            createBookmark(addr, "SVC", name);
        }
    }

    void doInitialize() {
        ctr_svcs.put((byte)0x03, "svcExitProcess");
        ctr_svcs.put((byte)0x01, "svcControlMemory");
        ctr_svcs.put((byte)0x02, "svcQueryMemory");
        ctr_svcs.put((byte)0x04, "svcGetProcessAffinityMask");
        ctr_svcs.put((byte)0x05, "svcSetProcessAffinityMask");
        ctr_svcs.put((byte)0x06, "svcGetProcessIdealProcessor");
        ctr_svcs.put((byte)0x07, "svcSetProcessIdealProcessor");
        ctr_svcs.put((byte)0x08, "svcCreateThread");
        ctr_svcs.put((byte)0x09, "svcExitThread");
        ctr_svcs.put((byte)0x0A, "svcSleepThread");
        ctr_svcs.put((byte)0x0B, "svcGetThreadPriority");
        ctr_svcs.put((byte)0x0C, "svcSetThreadPriority");
        ctr_svcs.put((byte)0x0D, "svcGetThreadAffinityMask");
        ctr_svcs.put((byte)0x0E, "svcSetThreadAffinityMask");
        ctr_svcs.put((byte)0x0F, "svcGetThreadIdealProcessor");
        ctr_svcs.put((byte)0x10, "svcSetThreadIdealProcessor");
        ctr_svcs.put((byte)0x11, "svcGetCurrentProcessorNumber");
        ctr_svcs.put((byte)0x12, "svcRun");
        ctr_svcs.put((byte)0x13, "svcCreateMutex");
        ctr_svcs.put((byte)0x14, "svcReleaseMutex");
        ctr_svcs.put((byte)0x15, "svcCreateSemaphore");
        ctr_svcs.put((byte)0x16, "svcReleaseSemaphore");
        ctr_svcs.put((byte)0x17, "svcCreateEvent");
        ctr_svcs.put((byte)0x18, "svcSignalEvent");
        ctr_svcs.put((byte)0x19, "svcClearEvent");
        ctr_svcs.put((byte)0x1A, "svcCreateTimer");
        ctr_svcs.put((byte)0x1B, "svcSetTimer");
        ctr_svcs.put((byte)0x1C, "svcCancelTimer");
        ctr_svcs.put((byte)0x1D, "svcClearTimer");
        ctr_svcs.put((byte)0x1E, "svcCreateMemoryBlock");
        ctr_svcs.put((byte)0x1F, "svcMapMemoryBlock");
        ctr_svcs.put((byte)0x20, "svcUnmapMemoryBlock");
        ctr_svcs.put((byte)0x21, "svcCreateAddressArbiter");
        ctr_svcs.put((byte)0x22, "svcArbitrateAddress");
        ctr_svcs.put((byte)0x23, "svcCloseHandle");
        ctr_svcs.put((byte)0x24, "svcWaitSynchronization1");
        ctr_svcs.put((byte)0x25, "svcWaitSynchronizationN");
        ctr_svcs.put((byte)0x26, "svcSignalAndWait");
        ctr_svcs.put((byte)0x27, "svcDuplicateHandle");
        ctr_svcs.put((byte)0x28, "svcGetSystemTick");
        ctr_svcs.put((byte)0x29, "svcGetHandleInfo");
        ctr_svcs.put((byte)0x2A, "svcGetSystemInfo");
        ctr_svcs.put((byte)0x2B, "svcGetProcessInfo");
        ctr_svcs.put((byte)0x2C, "svcGetThreadInfo");
        ctr_svcs.put((byte)0x2D, "svcConnectToPort");
        ctr_svcs.put((byte)0x2E, "svcSendSyncRequest1");
        ctr_svcs.put((byte)0x2F, "svcSendSyncRequest2");
        ctr_svcs.put((byte)0x30, "svcSendSyncRequest3");
        ctr_svcs.put((byte)0x31, "svcSendSyncRequest4");
        ctr_svcs.put((byte)0x32, "svcSendSyncRequest");
        ctr_svcs.put((byte)0x33, "svcOpenProcess");
        ctr_svcs.put((byte)0x34, "svcOpenThread");
        ctr_svcs.put((byte)0x35, "svcGetProcessId");
        ctr_svcs.put((byte)0x36, "svcGetProcessIdOfThread");
        ctr_svcs.put((byte)0x37, "svcGetThreadId");
        ctr_svcs.put((byte)0x38, "svcGetResourceLimit");
        ctr_svcs.put((byte)0x39, "svcGetResourceLimitLimitValues");
        ctr_svcs.put((byte)0x3A, "svcGetResourceLimitCurrentValues");
        ctr_svcs.put((byte)0x3B, "svcGetThreadContext");
        ctr_svcs.put((byte)0x3C, "svcBreak");
        ctr_svcs.put((byte)0x3D, "svcOutputDebugString");
        ctr_svcs.put((byte)0x3E, "svcControlPerformanceCounter");
        ctr_svcs.put((byte)0x47, "svcCreatePort");
        ctr_svcs.put((byte)0x48, "svcCreateSessionToPort");
        ctr_svcs.put((byte)0x49, "svcCreateSession");
        ctr_svcs.put((byte)0x4A, "svcAcceptSession");
        ctr_svcs.put((byte)0x4B, "svcReplyAndReceive1");
        ctr_svcs.put((byte)0x4C, "svcReplyAndReceive2");
        ctr_svcs.put((byte)0x4D, "svcReplyAndReceive3");
        ctr_svcs.put((byte)0x4E, "svcReplyAndReceive4");
        ctr_svcs.put((byte)0x4F, "svcReplyAndReceive");
        ctr_svcs.put((byte)0x50, "svcBindInterrupt");
        ctr_svcs.put((byte)0x51, "svcUnbindInterrupt");
        ctr_svcs.put((byte)0x52, "svcInvalidateProcessDataCache");
        ctr_svcs.put((byte)0x53, "svcStoreProcessDataCache");
        ctr_svcs.put((byte)0x54, "svcFlushProcessDataCache");
        ctr_svcs.put((byte)0x55, "svcStartInterProcessDma");
        ctr_svcs.put((byte)0x56, "svcStopDma");
        ctr_svcs.put((byte)0x57, "svcGetDmaState");
        ctr_svcs.put((byte)0x58, "svcRestartDma");
        ctr_svcs.put((byte)0x59, "svcSetGpuProt");
        ctr_svcs.put((byte)0x5A, "svcSetWifiEnabled");
        ctr_svcs.put((byte)0x60, "svcDebugActiveProcess");
        ctr_svcs.put((byte)0x61, "svcBreakDebugProcess");
        ctr_svcs.put((byte)0x62, "svcTerminateDebugProcess");
        ctr_svcs.put((byte)0x63, "svcGetProcessDebugEvent");
        ctr_svcs.put((byte)0x64, "svcContinueDebugEvent");
        ctr_svcs.put((byte)0x65, "svcGetProcessList");
        ctr_svcs.put((byte)0x66, "svcGetThreadList");
        ctr_svcs.put((byte)0x67, "svcGetDebugThreadContext");
        ctr_svcs.put((byte)0x68, "svcSetDebugThreadContext");
        ctr_svcs.put((byte)0x69, "svcQueryDebugProcessMemory");
        ctr_svcs.put((byte)0x6A, "svcReadProcessMemory");
        ctr_svcs.put((byte)0x6B, "svcWriteProcessMemory");
        ctr_svcs.put((byte)0x6C, "svcSetHardwareBreakPoint");
        ctr_svcs.put((byte)0x6D, "svcGetDebugThreadParam");
        ctr_svcs.put((byte)0x70, "svcControlProcessMemory");
        ctr_svcs.put((byte)0x71, "svcMapProcessMemory");
        ctr_svcs.put((byte)0x72, "svcUnmapProcessMemory");
        ctr_svcs.put((byte)0x73, "svcCreateCodeSet");
        ctr_svcs.put((byte)0x74, "svcRandomStub");
        ctr_svcs.put((byte)0x75, "svcCreateProcess");
        ctr_svcs.put((byte)0x76, "svcTerminateProcess");
        ctr_svcs.put((byte)0x77, "svcSetProcessResourceLimits");
        ctr_svcs.put((byte)0x78, "svcCreateResourceLimit");
        ctr_svcs.put((byte)0x79, "svcSetResourceLimitValues");
        ctr_svcs.put((byte)0x7A, "svcAddCodeSegment");
        ctr_svcs.put((byte)0x7B, "svcBackdoor");
        ctr_svcs.put((byte)0x7C, "svcKernelSetState");
        ctr_svcs.put((byte)0x7D, "svcQueryProcessMemory");
        ctr_svcs.put((byte)0xFF, "svcStopPoint");

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