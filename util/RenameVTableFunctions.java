// Names vtable function entries from RTTI inheritance, working off vtable data
// already discovered by RTTIUtil.
//
//   RenameVTableFunctions renamer = new RenameVTableFunctions(this);
//   renamer.run(program, vtableRttiSlots, typeinfoAddresses, monitor, state);
//
// @category RTTI
// @author Claude (for AlgebraManiacABC)

package util;

import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectData;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.*;
import java.util.regex.Pattern;

public class RenameVTableFunctions {

    private static final int PTR_SIZE = 4;

    // An adjustor thunk is a couple of instructions that fix up this and hand off.
    // Anything bigger that merely tail-calls a destructor is a real function.
    private static final int THUNK_MAX_BYTES = 32;

    // The placeholder names this script hands out. Secondary sub-vtables get the
    // function address appended, the same way the deleting destructor always has.
    private static final Pattern SLOT_PLACEHOLDER = Pattern.compile("V?F\\d{2,}(_.*)?");
    private static final Pattern DTOR_PLACEHOLDER = Pattern.compile("D[01](_.*)?");

    /**
     * Ghidra's own generated labels. These are not names -- they are addresses spelled out
     * -- and letting one through produced
     * {@code _ZN2nn3nex26DataStorePersistenceTarget12DAT_003b921cEv}, a symbol that reads
     * as armcc's and says nothing. {@code DAT_} in particular reaches a vtable slot
     * whenever Ghidra left the target's bytes as data rather than code.
     */
    private static final Pattern AUTO_LABEL = Pattern.compile(
            "(?:FUN|LAB|DAT|SUB|EXT|UNK|OFF|PTR|ARRAY|UNDEF|LOOP|COMP|CODE)"
            + "_[0-9a-fA-F]{6,}(?:_\\d+)?");

    /**
     * The unresolved-import handler keeps the name of the CRO header field that lists it
     * (3dbrew's and CRXLibrary's "OnUnresolved"): its real SDK symbol is unrecoverable, and
     * a documented format name is a more honest stand-in than one invented here. The fault
     * this pipeline fixes is that name leaking into class namespaces, not the name itself.
     */
    static final String HANDLER_NAME = "OnUnresolved";
    // The handler's "bx lr" tail (0x16d7f4 in ACNL) has no name. It was "OnUnresolved_return" for a while, but no field in the
    // files names it -- the header's OnUnresolved names only 0x7b1b88, which branches to
    // it -- so it stays FUN_0016d7f4, as the fixes doc asks.

    /** What earlier runs called the handler and its tail; removed if a saved project has them. */
    private static final Set<String> RETIRED_HANDLER_NAMES = Set.of(
            "cro_unresolved_import_handler", "cro_unresolved_import_return",
            "OnUnresolved_return");

    /** Names CRXLibrary gives the CRO header's entry points. */
    private static final Set<String> LOADER_ENTRY_NAMES = Set.of(
            "OnLoad", "OnExit", HANDLER_NAME);

    private static boolean isAutoLabel(String name) {
        return AUTO_LABEL.matcher(name).matches()
                || name.startsWith("thunk_")
                || name.startsWith("switchD_") || name.startsWith("caseD_")
                || name.startsWith("switchdataD_");
    }

    private final GhidraScript script;

    private SymbolTable symTab;
    private Memory mem;
    private Program program;

    // typeinfo address -> class name (fully qualified)
    private final Map<Long, String> typeinfoToClassName = new HashMap<>();
    // class name -> parent class names
    private final Map<String, List<String>> parentMap = new HashMap<>();
    // class name -> child class names
    private final Map<String, List<String>> childrenMap = new HashMap<>();
    // class name -> its bases, with the layout information parentMap throws away.
    // Kept alongside parentMap rather than replacing it: the name-only view has a
    // dozen readers that do not care where a base sits.
    private final Map<String, List<BaseRef>> baseInfoMap = new HashMap<>();
    // class name -> list of sub-vtable slot lists (index 0 = primary, 1+ = secondary)
    private final Map<String, List<List<Long>>> allVtableSlots = new HashMap<>();
    // class name -> primary vtable slot values
    private final Map<String, List<Long>> vtableSlots = new HashMap<>();
    // class name -> list of address points for each sub-vtable
    private final Map<String, List<Address>> allVtableAddressPoints = new HashMap<>();
    // class name -> primary vtable address point
    private final Map<String, Address> vtableAddressPoints = new HashMap<>();
    // class name -> list of sub-vtable heads: the offset-to-top word in front of each
    // RTTI slot. Index 0 is what _ZTV<class> points at. An entry is null when that
    // word is not readable.
    private final Map<String, List<Address>> allVtableHeads = new HashMap<>();
    // class name -> primary vtable head (the _ZTV address)
    private final Map<String, Address> vtableHeads = new HashMap<>();
    // class name -> Namespace
    private final Map<String, Namespace> classNamespaces = new HashMap<>();
    // class name -> the address its "typeinfo" label sits on, for the _ZTS spelling
    private final Map<String, Address> classTypeinfoAddrs = new HashMap<>();
    // class name -> the function-slot struct of each sub-vtable, parallel to
    // allVtableHeads. A vptr holds an address point, so these -- not the structs
    // applied to memory -- are what a class struct's vtable fields point at.
    private final Map<String, List<Structure>> classVfuncs = new HashMap<>();

    // Set of all known typeinfo addresses
    private final Set<Long> typeinfoAddresses = new HashSet<>();
    // operator delete addresses (thumb bit masked), found by agreement
    private final Set<Long> operatorDeleteAddrs = new HashSet<>();
    // __cxa_pure_virtual address (thumb bit masked)
    private long pureVirtualAddr = 0;
    private boolean externalPureVirtual = false;

    private final Set<String> processed = new HashSet<>();
    // class name -> code addresses writing its own or an ancestor's vtable pointer
    private final Map<String, Set<Address>> vtableWriterCache = new HashMap<>();
    // class name -> index of D1 in its primary sub-vtable, once known
    private final Map<String, Integer> dtorSlot = new HashMap<>();
    private final Map<String, Program> importedPrograms = new HashMap<>();

    private int renameCount = 0;
    private int skipCount = 0;
    private int pureVirtualCount = 0;

    // Which rule identified each destructor pair â€” printed once per run, so a single
    // run says where detection is working and where it is falling through.
    private int dtorByThunk = 0;
    private int dtorByDelete = 0;
    private int dtorByWrite = 0;
    private int dtorByInherit = 0;
    private int dtorNone = 0;
    private int dtorExtraPairs = 0;
    private int dtorByScan = 0;
    private int dtorByBaseCall = 0;
    private int dtorTrailingDropped = 0;
    /** Pairs chosen without D0 sitting below D1, so the address evidence was absent. */
    private int dtorUnordered = 0;
    /** Pairs whose bodies differed by exactly one call -- the strongest signal there is. */
    private int dtorByShape = 0;
    /** Pairs pinned to the index the hierarchy's root established. */
    private int dtorByInheritedIndex = 0;
    /** Tables where a slot ended in a deallocator, so the pair was read off, not scored. */
    private int dtorByDeallocTail = 0;
    /** Tables with no deallocating slot at all, left to shape and address alone. */
    private int dtorNoDeallocTail = 0;
    private final Map<Address, List<Address>> callTargetCache = new HashMap<>();

    /** Unrelated classes that must agree before a call is believed to be operator delete. */
    private static final int MIN_OPERATOR_DELETE_AGREEMENT = 3;

    /** How far below the best-agreed deallocator a candidate may sit and still count. */
    private static final int OPERATOR_DELETE_TAIL_RATIO = 20;
    private int branchStubsSkipped = 0;

    /** Slots named _ZTv: thunks that load their this-adjustment from a vcall offset. */
    private int virtualThunkCount = 0;

    /** _ZT_B1_ tables whose virtual base could not be named, so no mangled name was written. */
    private int ctorVbaseUnnamed = 0;
    private int ctorDepthUnnamed = 0;
    private int ctorNameAmbiguous = 0;
    private int ctorSubstitutionUnnamed = 0;

    /** Secondary sub-tables matched to a base by offset-to-top, and by position instead. */
    private int subVtableByOffset = 0;
    private int subVtableByPosition = 0;

    /** Instruction cap for the body-independent vtable-writer scan. */
    private static final int MAX_BODY_SCAN = 2048;

    /** At or below this, a recorded body is a stub rather than the function. */
    private static final int DEGENERATE_BODY_BYTES = 4;

    // Vtable slots are in declaration order, so the destructor pair can sit anywhere --
    // armcc settles this. What pins it down instead is address: D0Ev sorts before D1Ev
    // and both sort after every other member, so the pair is the last two functions of
    // the class, D0 immediately below D1. See chooseDestructorPair.

    // class name -> every ancestor of it, transitively
    private final Map<String, Set<String>> ancestorCache = new HashMap<>();

    /**
     * The scan that decides which tables are whose. Kept for the sub-table geometry the
     * struct builder and the base matcher need, and for the VTT and construction-vtable
     * labels.
     */
    private VtableScan vtableScan;

    /** class name -> the sub-tables of its own vtable, in address order. */
    private final Map<String, List<VtableScan.SubTable>> allVtableSubTables =
            new LinkedHashMap<>();

    public RenameVTableFunctions(GhidraScript script) {
        this.script = script;
    }

    // ---------------------------------------------------------------
    //  Public API
    // ---------------------------------------------------------------

    /**
     * Run the vtable rename pipeline.
     *
     * @param vtableRttiSlots  Map of vtable RTTI slot address -> typeinfo address
     * @param knownTypeinfos   Set of all known typeinfo struct addresses
     */
    public void run(Program prog, Map<Long, Long> vtableRttiSlots, Set<Long> knownTypeinfos,
                    TaskMonitor monitor, GhidraState state)
            throws Exception {
        // A CRO opened for its typeinfo is held as a consumer until released, and the
        // release used to sit at the bottom of the pipeline where anything thrown above it
        // skipped it -- leaving the module pinned open for the rest of the session and
        // Ghidra reporting a leaked consumer on shutdown. RTTIUtil already guards its own
        // opens this way; this is the same guarantee for the pipeline as a whole.
        try {
            runPipeline(prog, vtableRttiSlots, knownTypeinfos, monitor, state);
        } finally {
            releaseImportedPrograms();
        }
    }

    /**
     * Let go of every CRO this pass opened. Safe to call more than once.
     *
     * <p>Including the module being processed, if a cross-module reference led back to it.
     * Every entry in this map came from {@code getDomainObject}, which takes a consumer
     * reference whoever the program turns out to be; skipping the one that happens to
     * equal {@code program} gave back one fewer reference than were taken, and Ghidra
     * reported the difference as a leaked consumer when the project closed. Releasing does
     * not close anything -- the tool holds its own reference to the program it has open.
     */
    private void releaseImportedPrograms() {
        for (Program p : importedPrograms.values()) {
            if (p == null) continue;
            try {
                p.release(script);
            } catch (Exception e) {
                script.println("WARNING: could not release " + p.getName());
            }
        }
        importedPrograms.clear();
    }

    private void runPipeline(Program prog, Map<Long, Long> vtableRttiSlots,
                             Set<Long> knownTypeinfos,
                             TaskMonitor monitor, GhidraState state)
            throws Exception {
        // Clear state from any previous run
        typeinfoToClassName.clear();
        typeinfoIn.clear();
        parentMap.clear();
        childrenMap.clear();
        baseInfoMap.clear();
        allVtableSlots.clear();
        vtableSlots.clear();
        allVtableAddressPoints.clear();
        vtableAddressPoints.clear();
        allVtableHeads.clear();
        vtableHeads.clear();
        classNamespaces.clear();
        classTypeinfoAddrs.clear();
        classVfuncs.clear();
        typeinfoAddresses.clear();
        operatorDeleteAddrs.clear();
        processed.clear();
        vtableWriterCache.clear();
        dtorSlot.clear();
        importedPrograms.clear();
        pureVirtualAddr = 0;
        externalPureVirtual = false;
        renameCount = 0;
        skipCount = 0;
        pureVirtualCount = 0;
        dtorByThunk = 0;
        dtorByDelete = 0;
        dtorByWrite = 0;
        dtorByInherit = 0;
        dtorNone = 0;
        dtorExtraPairs = 0;
        dtorByScan = 0;
        dtorByBaseCall = 0;
        dtorTrailingDropped = 0;
        dtorUnordered = 0;
        dtorByShape = 0;
        dtorByInheritedIndex = 0;
        dtorByDeallocTail = 0;
        dtorNoDeallocTail = 0;
        deallocatorTailCache.clear();
        callTargetCache.clear();
        branchStubsSkipped = 0;
        slotOwner.clear();
        contestedTargets.clear();
        foreignRecoveredNames.clear();
        foreignNamesDropped = 0;
        foreignNamesKept = 0;
        constructionOnlyNamed = 0;
        constructionOnlyClasses = 0;
        constructionOnlyAddrs.clear();
        allSlotTargets.clear();
        unresolvedImportHandler = null;
        pltEntriesNamed = 0;
        pltEntriesUnnamed = 0;
        pltEntriesAnonymous = 0;
        veneerTargetUnnamed = 0;
        pltEntries.clear();
        ownersAssigned = 0;
        ownersContested = 0;
        slotsOwnedElsewhere = 0;
        predictedThunks.clear();
        secondaryAdjust.clear();
        thunksPredicted = 0;
        thunksContested = 0;
        thunkBodyAgreed = 0;
        thunkBodyDisagreed = 0;
        thunkVcallDisagreed = 0;
        thunkOffsetDisagreed = 0;
        thunkDisagreements.clear();
        disagreementsByClass.clear();
        bodyConstantCache.clear();
        placeholdersLeftUnmangled = 0;
        methodsLeftUnmangled = 0;
        veneersSplitOut = 0;
        thunkKindConflicts = 0;
        thunkKindConflictExamples.clear();
        hostsEnded = 0;
        hostsEndedExamples.clear();
        modeRedecoded = 0;
        pureDestructors = 0;
        signaturesInherited = 0;
        signatureSeeds = 0;
        ownersOutsideSet = 0;
        hierarchyIncomplete = 0;
        noAncestorExamples.clear();
        kindsFromAbiVtable = 0;
        kindsOverridingStruct = 0;
        kindOverrideExamples.clear();
        absentOwnerNamed = 0;
        mangledPlans.clear();
        ambiguousMangled.clear();
        mangledNamesSuppressed = 0;
        mangledAliasAddrs.clear();
        virtualThunkCount = 0;
        ctorVbaseUnnamed = 0;
        ctorVbaseExamples.clear();
        ctorAmbiguousExamples.clear();
        ctorDepthUnnamed = 0;
        ctorNameAmbiguous = 0;
        ctorSubstitutionUnnamed = 0;
        subVtableByOffset = 0;
        subVtableByPosition = 0;
        ancestorCache.clear();
        allVtableSubTables.clear();
        vtableScan = null;

        program = prog;
        symTab = prog.getSymbolTable();
        mem = prog.getMemory();
        typeinfoAddresses.addAll(knownTypeinfos);

        script.printf("=== RTTI Renaming Pipeline for %s ===\n",program.getName());

        // Step 1: Find __cxa_pure_virtual
        findPureVirtual();

        // Step 2: Build inheritance tree from typeinfo symbols
        buildInheritanceTree();
        script.printf("    Classes found: %d ", typeinfoToClassName.size());

        // Step 3: Group the discovered tables into whole vtable objects, and keep only
        // the group that is each class's own. The rest carry its typeinfo but were
        // emitted for classes deriving from it.
        ingestGroups(vtableRttiSlots, monitor);
        script.printf("(%d with vtable data)\n", vtableSlots.size());

        // Step 4: If __cxa_pure_virtual wasn't found by symbol, detect by vtable analysis
        if (pureVirtualAddr == 0 && !externalPureVirtual) {
            detectPureVirtual();
        }
        if (pureVirtualAddr == 0 && !externalPureVirtual) {
            script.printf("    WARNING: No __cxa_pure_virtual for %s\n",program.getName());
        }

        // Step 4.5: Read the grouping back through slot 0, looking for hierarchies that
        // share one and so are probably one hierarchy. Runs here rather than straight
        // after ingestGroups so the pure-virtual address detectPureVirtual just found
        // can be excluded from the comparison -- every abstract class shares it.
        linkHierarchiesBySlotZero();

        // Step 5: Collect namespace objects
        collectNamespaces();

        // Step 6: Every destructor test reads a function body, so the slot targets
        // have to exist before any of them runs.
        int materialised = ensureVtableFunctions();

        // Step 6.5: Analysis has to catch up with the code step 6 just disassembled.
        // writesOwnVtable asks which functions reference a vtable address point, and
        // those references are made by the analyzers that run over newly disassembled
        // code -- not by the disassembly itself. Naming without waiting reads a
        // reference set that predates half the program's code, so a destructor whose
        // function this run created reads as an ordinary slot and gets VF<nn>. It also
        // means a second run of the pipeline would name what the first one missed,
        // which is exactly what was observed.
        if (materialised > 0) {
            script.printf("    Created %d slot functions; running analysis so their " +
                    "references exist before naming\n", materialised);
            script.analyzeChanges(program);
            // Anything cached from before the analysis is built on the old references.
            vtableWriterCache.clear();
        }

        // Step 7: Note where operator delete lives, as a tiebreaker for D0. When the
        // symbol table never named it, the destructor pairs give it away themselves --
        // and this has to run before any class is processed, so the classes can use it.
        collectSlotTargets();
        // Before ownership, because the unresolved-import handler must not be treated as
        // anyone's method: dozens of CRO classes have a slot pointing at it.
        surveyImportStubs();
        clearLoaderNamesOnMethods();
        collectPureVirtualChain();
        nameRuntimeChain();
        collectOperatorDeletes();
        // Always, not only when the symbol table named none. ACNL links a deallocator per
        // module -- twelve of them -- and a symbol on one says nothing about the other
        // eleven, so stopping here left endsInDeallocator blind to most of the image.
        detectOperatorDelete();

        // Step 7b: Work out which class owns each slot target, from every table in the
        // image, before any of them is named.
        assignSlotOwners();
        predictThunkAdjustments();

        // Step 8: Process in topological order (Kahn's algorithm)

        Map<String, Integer> inDegree = new HashMap<>();
        for (String className : typeinfoToClassName.values()) {
            inDegree.put(className, 0);
        }
        for (Map.Entry<String, List<String>> entry : parentMap.entrySet()) {
            inDegree.put(entry.getKey(), entry.getValue().size());
        }

        ArrayDeque<String> queue = new ArrayDeque<>();
        for (Map.Entry<String, Integer> entry : inDegree.entrySet()) {
            if (entry.getValue() == 0) {
                queue.add(entry.getKey());
            }
        }

        while (!queue.isEmpty()) {
            String className = queue.poll();
            processClass(className);

            List<String> children = childrenMap.get(className);
            if (children != null) {
                for (String child : children) {
                    int remaining = inDegree.get(child) - 1;
                    inDegree.put(child, remaining);
                    if (remaining == 0) {
                        queue.add(child);
                    }
                }
            }
        }

        // Step 8b: The classes the walk could not visit at all, because every table
        // carrying their typeinfo belongs to someone else's constructor.
        nameConstructionOnlyClasses();
        if (constructionOnlyClasses > 0) {
            script.printf("    Construction-only:      %d slots named in %d classes whose " +
                    "only tables are other classes' construction vtables\n",
                    constructionOnlyNamed, constructionOnlyClasses);
        }

        // Step 9: Propagate discovered names upward through the hierarchy
        propagateNames();

        // Step 9b: Pick up the thunks the walk could not reach, now that everything it
        // could name has a name and hasRealName can tell the difference.
        nameOrphanDestructorThunks();

        // Step 10: Add the mangled spelling of each name alongside it
        // emitMangledNames is what fills virtualThunkCount, so it is read out of the
        // printf rather than called inside it.
        int functionNames = emitMangledNames();
        script.printf("    Mangled names added:    %d function (%d of them _ZTv virtual " +
                "adjustor thunks), %d vtable (_ZTV), " +
                "%d VTT/construction (_ZTT, _ZT_C1_, _ZT_B1_)\n",
                functionNames, virtualThunkCount, emitMangledVtableNames(),
                emitVttAndConstructionNames());
        if (ctorDepthUnnamed > 0 || ctorNameAmbiguous > 0) {
            script.printf("    Construction vtables:   %d left unmangled (no derivation path " +
                    "from the table's class to its owner), %d names dropped as ambiguous\n",
                    ctorDepthUnnamed, ctorNameAmbiguous);
            for (String ex : ctorAmbiguousExamples) script.println("        " + ex);
        }
        if (ctorVbaseUnnamed > 0) {
            script.printf("    Construction vtables:   %d _ZT_B1_ tables left unmangled " +
                    "(their typeinfo class names no single virtual base)\n",
                    ctorVbaseUnnamed);
            for (String ex : ctorVbaseExamples) script.println("        " + ex);
        }
        script.printf("    Branch stubs:           %d lone branches un-thunked and named " +
                "as the functions they are\n", branchStubsSkipped);
        script.printf("    Slot ownership:         %d slots left to a less-derived class " +
                "that declares them (%d named in an owner with no vtable of its own)\n",
                slotsOwnedElsewhere, absentOwnerNamed);
        // No thunk body cross-check is reported any more. armcc folds the this-adjustment
        // into member displacements, ADD chains and literal-pool constants, under -Ospace
        // as well as -Otime (open answers 2, Q13: _ZThn8504_N2C23getEv is LDR r0,[r0,#4]),
        // so a body that does not show it is normal and the count meant nothing. The
        // table's offset-to-top is what names a thunk.
        script.printf("    Placeholders:           %d slots left unmangled because only the " +
                "class, not the method name, was recovered\n", placeholdersLeftUnmangled);
        script.printf("    Signatures:             %d method names left as plain labels "
                + "(parameters and const-ness unknown); %d spelled from a real symbol's "
                + "signature (%d seeds, inherited by overriders)\n",
                methodsLeftUnmangled, signaturesInherited, signatureSeeds);
        emitBaseObjectDestructors();
        nameBaseDestructorsFromTailCalls();
        detachMirroringFragments();
        nameLinkerVeneers();
        pruneStaleMangledNames();
        // Again, and last. Clearing the handler's name during step 7b is what lets the
        // ownership pass treat it as nobody's method, but something downstream puts a name
        // back on it -- 66 vtable slots point there, so several passes have an opinion --
        // and only a pass that runs after all of them can be sure the name is gone.
        nameNeutral(unresolvedImportHandler, HANDLER_NAME);
        clearToDefault(unresolvedImportTail);

        script.printf("    Secondary sub-tables:   %d matched to a base by offset-to-top, " +
                "%d by declaration order\n", subVtableByOffset, subVtableByPosition);

        script.printf("    Destructor pairs:       %d read off the deallocating tail, " +
                "%d with no deallocating slot (scored instead)\n",
                dtorByDeallocTail, dtorNoDeallocTail);
        script.printf("                            %d settled by shape (D0 is D1 plus one " +
                "call), %d pinned to the index the hierarchy's root set\n",
                dtorByShape, dtorByInheritedIndex);
        script.printf("    Destructor slots:       %d thunk, %d op-delete, %d vtable-write " +
                "(%d of them past a short body), %d base-dtor call, %d inherited; " +
                "%d sub-vtables with none, %d rival pairs dropped on address, " +
                "%d halves with no room for their partner, " +
                "%d pairs chosen without D0 below D1\n",
                dtorByThunk, dtorByDelete, dtorByWrite, dtorByScan, dtorByBaseCall,
                dtorByInherit, dtorNone, dtorExtraPairs, dtorTrailingDropped,
                dtorUnordered);

        // Step 11: Assemble vtable structs for pretty decomp
        buildVtableStructs();
        buildConstructionVtableStructs();

        // Report unreached classes
        int unreached = 0;
        for (String className : vtableSlots.keySet()) {
            if (!processed.contains(className)) {
                unreached++;
                if (unreached <= 20) {
                    script.println("    UNREACHED: " + className +
                            " (parent: " + parentMap.getOrDefault(className, List.of()) + ")");
                }
            }
        }
        if (unreached > 20) {
            script.println("... and " + (unreached - 20) + " more unreached classes.");
        }

        script.printf("    Slot targets:           %d made functions that no naming walk had "
                + "reached\n", ensureAllSlotTargetsAreFunctions());
        script.printf("    Code pointers:          %d relocated .rodata pointers into .text "
                + "made functions\n", ensureRelocatedCodePointersAreFunctions());
        if (pureDestructors > 0) {
            script.printf("    Destructor pairs:       %d tables with a pure virtual destructor "
                    + "(no D1/D0 looked for elsewhere)\n", pureDestructors);
        }
        if (modeRedecoded > 0) {
            script.printf("    Instruction set:        %d entries redecoded in the mode their "
                    + "pointer gives\n", modeRedecoded);
        }
        if (thunkKindConflicts > 0) {
            script.printf("    WARNING: %d thunks left unnamed: the table says virtual, the " +
                    "body adjusts this by a constant and never reads the vtable\n",
                    thunkKindConflicts);
            for (String s : thunkKindConflictExamples) script.println("        " + s);
        }
        if (hostsEnded > 0) {
            script.printf("    Function boundaries:    %d functions ended before an entry point " +
                    "their body had run across\n", hostsEnded);
            for (String ex : hostsEndedExamples) script.println("        " + ex);
        }
        script.println("    " + settleLinkerStubs(program));
        releaseImportedPrograms();
    }

    /**
     * Last word on the linker's own stubs, run after everything else has touched the
     * program. Works from names alone so CROLink can call it again once analysis has
     * finished on every module.
     *
     * <ul>
     * <li>A PLT entry or veneer that is a Ghidra thunk again is un-thunked. Something after
     *     nameLinkerVeneers turns 23 PLT entries and some veneers back into thunks; plain
     *     analysis does not (DiagnoseThunkRevert), so this does not guess which pass.</li>
     * <li>A thunk <em>to</em> a veneer is detached. 0x301560 and 0x838768 are lone B
     *     instructions chaining to the veneer at 0x49cbe8; as thunks they displayed its
     *     $Ven$ name, and read as two more veneers.</li>
     * <li>The handler's tail is cut out of the handler's body and made a function of its
     *     own. Ghidra had folded the "bx lr" at 0x16d7f4 into the handler as a second
     *     range, which the export wrote as cro_unresolved_import_handler_0016d7f4.</li>
     * </ul>
     */
    public static String settleLinkerStubs(Program p) {
        int unthunked = 0, detached = 0, carved = 0;
        FunctionIterator it = p.getFunctionManager().getFunctions(true);
        List<Function> stubs = new ArrayList<>();
        while (it.hasNext()) {
            Function f = it.next();
            String n = f.getSymbol().getName();
            // <target>@<soname> (pltName; the soname may be |static|), $Ven$... (veneers),
            // and plt_... from older runs
            if (n.startsWith("plt_") || n.startsWith("$Ven$") || n.matches(".+@(Module\\w+|\\|static\\|)")
                    || isPltEntry(p, f.getEntryPoint())) {
                stubs.add(f);
            }
        }
        for (Function f : stubs) {
            try {
                if (f.isThunk()) {
                    f.setThunkedFunction(null);
                    unthunked++;
                }
                if (f.getSymbol().getName().startsWith("$Ven$")) {
                    for (Address t : Optional.ofNullable(f.getFunctionThunkAddresses(false))
                            .orElse(new Address[0])) {
                        Function thunk = p.getFunctionManager().getFunctionAt(t);
                        if (thunk != null && thunk.isThunk()) {
                            thunk.setThunkedFunction(null);
                            detached++;
                        }
                    }
                }
            } catch (Exception e) {
                // Leave this one; the rest still get done.
            }
        }
        // The tail has no name to look it up by: it is wherever the handler branches.
        SymbolIterator handlers = p.getSymbolTable().getSymbols(HANDLER_NAME);
        while (handlers.hasNext()) {
            Address tail = firstUnconditionalJump(p, handlers.next().getAddress());
            if (tail != null && carveOut(p, tail)) carved++;
        }
        return String.format("Linker stubs settled:   %d PLT entries/veneers un-thunked again, "
                + "%d thunks to a veneer detached, %d handler tails made functions",
                unthunked, detached, carved);
    }

    /**
     * Make {@code at} a function of its own when another function's body has absorbed it
     * as a separate range. Only that range is taken, and only when it does not hold the
     * other function's entry.
     */
    /**
     * An {@code LDR pc,[pc,#-4]} stub with an import record on it or its literal: a PLT
     * entry, recognised by what it is rather than what it is called. A Ghidra thunk reports
     * its target's name, not its own, so the name test above misses exactly the entries
     * analysis has turned back into thunks -- and the export skips a thunk that carries an
     * import record, which is how 638 CRO PLT entries (every one reaching a code.bin D1)
     * had no row at all.
     */
    private static boolean isPltEntry(Program p, Address entry) {
        try {
            if (p.getMemory().getInt(entry) != 0xe51ff004) return false;
        } catch (Exception e) {
            return false;
        }
        for (Address a : new Address[]{entry, entry.add(4)}) {
            for (Reference r : p.getReferenceManager().getReferencesFrom(a)) {
                if (r instanceof ExternalReference) return true;
            }
        }
        return false;
    }

    /** The target of the first unconditional branch in the few instructions from {@code start}. */
    private static Address firstUnconditionalJump(Program p, Address start) {
        Address a = start;
        for (int i = 0; i < 4 && a != null; i++) {
            Instruction ins = p.getListing().getInstructionAt(a);
            if (ins == null) return null;
            if (ins.getFlowType().isJump() && ins.getFlowType().isUnConditional()) {
                Address[] flows = ins.getFlows();
                return (flows.length == 1) ? flows[0] : null;
            }
            a = ins.getMaxAddress().next();
        }
        return null;
    }

    private static boolean carveOut(Program p, Address at) {
        FunctionManager fm = p.getFunctionManager();
        if (fm.getFunctionAt(at) != null) return false;
        Function host = fm.getFunctionContaining(at);
        if (host == null) return false;
        AddressRange range = host.getBody().getRangeContaining(at);
        if (range == null || range.contains(host.getEntryPoint())) return false;
        try {
            AddressSet body = new AddressSet(host.getBody());
            body.delete(range);
            host.setBody(body);
            fm.createFunction(null, at, new AddressSet(range), SourceType.DEFAULT);
            Symbol s = fm.getFunctionAt(at).getSymbol();
            for (Symbol other : p.getSymbolTable().getSymbols(at)) {
                if (!other.equals(s) && other.getSource() != SourceType.DEFAULT) {
                    String name = other.getName();
                    Namespace ns = other.getParentNamespace();
                    other.delete();
                    s.setNameAndNamespace(name, ns, SourceType.ANALYSIS);
                    break;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // ---------------------------------------------------------------
    //  Pure virtual detection
    // ---------------------------------------------------------------

    private void findPureVirtual() {
        SymbolIterator iter = program.getSymbolTable().getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            if (sym.getName().contains("__cxa_pure_virtual")) {
                pureVirtualAddr = sym.getAddress().getOffset();
                script.println("Found __cxa_pure_virtual at 0x" +
                        Long.toHexString(pureVirtualAddr));
                return;
            }
        }

        ReferenceManager refMan = program.getReferenceManager();
        ReferenceIterator refIter = refMan.getExternalReferences();
        while (refIter.hasNext()) {
            if (refIter.next() instanceof ExternalReference extRef) {
                if (extRef.getLabel().contains("__cxa_pure_virtual")) {
                    pureVirtualAddr = extRef.getExternalLocation()
                            .getAddress().getOffset();
                    externalPureVirtual = true;
                    script.println("Found __cxa_pure_virtual at 0x" +
                            Long.toHexString(pureVirtualAddr) +
                            " within " + extRef.getLibraryName());
                    return;
                }
            }
        }
    }

    private boolean isPureVirtualRef(Address addr) throws MemoryAccessException {
        if (pureVirtualAddr == 0) return false;
        if (externalPureVirtual) {
            ReferenceManager refMan = program.getReferenceManager();
            Reference[] refs = refMan.getReferencesFrom(addr);
            for (Reference ref : refs) {
                if (ref instanceof ExternalReference extRef) {
                    if (extRef.getLabel().contains("cxa_pure_virtual"))
                        return true;
                    if (extRef.getExternalLocation().getAddress().equals(addr))
                        return true;
                }
            }
            return false;
        }
        long funcPtr = Integer.toUnsignedLong(program.getMemory().getInt(addr));
        return (funcPtr & ~1L) == (pureVirtualAddr & ~1L);
    }

    // ---------------------------------------------------------------
    //  Inheritance tree
    // ---------------------------------------------------------------

    private void buildInheritanceTree() throws Exception {
        collectTypeinfoSymbols(program);

        for (Map.Entry<Long, String> entry :
                new ArrayList<>(typeinfoToClassName.entrySet())) {
            resolveParents(program, entry.getKey(), entry.getValue());
        }
        script.printf("    Typeinfo kinds:         %d read from the ABI vtable their first " +
                "word points at, %d of them overriding an applied struct of another kind\n",
                kindsFromAbiVtable, kindsOverridingStruct);
        for (String ex : kindOverrideExamples) script.println("        " + ex);

        releaseImportedPrograms();
    }

    private int kindsFromAbiVtable = 0;
    private int kindsOverridingStruct = 0;
    private final List<String> kindOverrideExamples = new ArrayList<>();

    /**
     * A typeinfo's kind, read from which of the three {@code __cxxabiv1} vtables its first
     * word points at -- the one fact that decides it -- or null when that cannot be named.
     *
     * <p>In a CRO the word is an import from the static module, so the answer is in
     * code.bin's labels at the import's target. The struct applied at the typeinfo is not
     * evidence of equal weight. ExportClassHierarchy, reading the kind from the import,
     * resolves every ancestor of {@code escape::BsEscapeModelPickupEvent} through
     * {@code ModuleMiniGame0.cro} to {@code UtlBase<Base>}; this pass, reading the applied
     * length, left {@code 0x81f57c} and {@code 0x81f618} -- listed by 23 classes that all
     * descend from {@code UtlBase<Base>} -- with no owner, and they took a subclass's
     * name. Whether the length was the break is what the counters below report.
     */
    private String abiKindOfTypeinfo(Program p, Address ti) {
        Program target = p;
        long offset = -1;
        for (Reference ref : p.getReferenceManager().getReferencesFrom(ti)) {
            if (!(ref instanceof ExternalReference extRef)) continue;
            ExternalLocation loc = extRef.getExternalLocation();
            if (loc.getAddress() == null) continue;
            Library lib = p.getExternalManager().getExternalLibrary(loc.getLibraryName());
            if (lib == null || lib.getAssociatedProgramPath() == null) continue;
            Program prog = openCroProgram(lib.getAssociatedProgramPath());
            if (prog == null) continue;
            target = prog;
            offset = loc.getAddress().getOffset();
            break;
        }
        if (offset < 0) {
            try {
                offset = Integer.toUnsignedLong(p.getMemory().getInt(ti));
            } catch (MemoryAccessException e) {
                return null;
            }
        }
        // The word is normally the address point, _ZTV+8, but an import record can name the
        // head. Ask the exact address first: at the address point, head-8 is the previous
        // ABI class's vtable, so trying it first would answer with the wrong class.
        String kind = abiVtableKindAt(target, offset);
        return (kind != null) ? kind : abiVtableKindAt(target, offset - 8);
    }

    private static String abiVtableKindAt(Program p, long offset) {
        if (offset < 0) return null;
        Address at;
        try {
            at = p.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        } catch (Exception e) {
            return null;
        }
        for (Symbol s : p.getSymbolTable().getSymbols(at)) {
            String name = s.getName(true);
            if (name.startsWith("_ZTI") || name.startsWith("_ZTS")
                    || !(name.startsWith("_ZTV") || name.contains("vtable"))) continue;
            if (name.contains("__vmi_class_type_info")) return "__vmi_class_type_info";
            if (name.contains("__si_class_type_info")) return "__si_class_type_info";
            if (name.contains("__class_type_info")) return "__class_type_info";
        }
        return null;
    }

    private void collectTypeinfoSymbols(Program program) {
        SymbolIterator iter = program.getSymbolTable().getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            if (!sym.getName().equals("typeinfo")) continue;
            // An imported typeinfo (a named import of _ZTI..., demangled into
            // |static|::X::typeinfo) has an external-space address; read as an offset into
            // this program it lands in the CRO header. MLDT's named imports produced 166
            // "Could not determine RTTI type" warnings that way. Bases in other modules
            // are followed through the import record in resolveBaseType instead.
            if (sym.isExternal()) continue;

            Namespace ns = sym.getParentNamespace();
            if (ns == null || ns.isGlobal()) continue;

            long addr = sym.getAddress().getOffset();
            String className = ns.getName(true);

            // Skip __cxxabiv1 infrastructure classes
            if (className.startsWith("__cxxabiv1")) continue;

            typeinfoIn.computeIfAbsent(program, k -> new HashMap<>())
                    .putIfAbsent(addr, className);
            if (!typeinfoToClassName.containsKey(addr)) {
                typeinfoToClassName.put(addr, className);
                typeinfoAddresses.add(addr);
            }
        }
    }

    /**
     * program -> (typeinfo offset -> class), for resolving a base word in the program it
     * was read from. typeinfoToClassName is keyed by the bare offset and gathers every
     * module's typeinfos, so one module's offset could answer for another's.
     */
    private final Map<Program, Map<Long, String>> typeinfoIn = new HashMap<>();

    private void resolveParents(Program program, long tiAddr, String className)
            throws Exception {
        if (parentMap.containsKey(className)) return;

        Memory progMem = program.getMemory();
        Listing progListing = program.getListing();
        Address addr = program.getAddressFactory()
                .getDefaultAddressSpace().getAddress(tiAddr);

        // The ABI vtable the first word points at *is* the kind; the applied struct only
        // repeats it, and in a CRO it can repeat it wrongly (see abiKindOfTypeinfo).
        String byVtable = abiKindOfTypeinfo(program, addr);
        String bySize = null;
        Data data = progListing.getDataAt(addr);
        if (data != null) {
            int size = data.getLength();
            if (size == 8) bySize = "__class_type_info";
            else if (size == 12) bySize = "__si_class_type_info";
            else if (size >= 16) bySize = "__vmi_class_type_info";
        }
        String rttiType = (byVtable != null) ? byVtable : bySize;
        if (byVtable != null) kindsFromAbiVtable++;
        if (byVtable != null && bySize != null && !byVtable.equals(bySize)) {
            kindsOverridingStruct++;
            if (kindOverrideExamples.size() < MAX_DISAGREEMENT_EXAMPLES) {
                kindOverrideExamples.add(String.format("%s @ %s in %s: struct says %s, " +
                        "ABI vtable says %s", className, addr, program.getName(), bySize,
                        byVtable));
            }
        }
        if (rttiType == null) {
            if (className.contains("vmi_class")) rttiType = "__vmi_class_type_info";
            else if (className.contains("si_class")) rttiType = "__si_class_type_info";
            else if (className.contains("class_type")) rttiType = "__class_type_info";
        }
        if (rttiType == null) {
            script.println("    WARNING: Could not determine RTTI type for " +
                    className + " at " + addr + " in " + program.getName());
            return;
        }

        switch (rttiType) {
            case "__class_type_info" -> {}
            // A __si base is always public, non-virtual and at offset 0. Synthesize the
            // equivalent __offset_flags so every edge is described the same way.
            case "__si_class_type_info" ->
                    resolveBaseType(program, addr.add(8), className, BaseRef.PUBLIC_MASK);
            case "__vmi_class_type_info" -> {
                int baseCount = progMem.getInt(addr.add(12));
                for (int b = 0; b < baseCount; b++) {
                    // __base_class_type_info = { const __class_type_info *__base_type;
                    //                            long __offset_flags; }
                    Address baseEntry = addr.add(16 + b * 8L);
                    resolveBaseType(program, baseEntry, className,
                            progMem.getInt(baseEntry.add(4)));
                }
            }
        }
    }

    private void resolveBaseType(Program program,
                                 Address baseFieldAddr,
                                 String childClassName,
                                 int offsetFlags) throws Exception {
        Memory progMem = program.getMemory();
        long basePtr = Integer.toUnsignedLong(progMem.getInt(baseFieldAddr));

        // Looked up in the word's own program, and followed upward. This used to consult
        // the all-modules map and stop at the first edge, relying on buildInheritanceTree's
        // loop to reach the parent -- but that loop covers only this program's typeinfos,
        // snapshotted before any CRO was opened. esc::BsEscModelBase, reached as
        // escape::BsEscapeModelPickup's same-module base in ModuleMiniGame0, was therefore
        // never resolved itself: its edge to UtlBase<Base> was lost, 13 slot targets had no
        // common ancestor, and 0x81f57c/0x81f618 took escape::BsEscapeModelPickupEvent's name.
        String parentName = typeinfoIn.getOrDefault(program, Map.of()).get(basePtr);
        if (parentName != null) {
            addParentChild(childClassName, parentName, offsetFlags);
            resolveParents(program, basePtr, parentName);
            return;
        }

        // An import record on the word is what says the base lives elsewhere, whatever the
        // word holds. Gating this on the word pointing at a symbol named "OnUnresolved"
        // tied every cross-module edge to the one name nameNeutral exists to remove: the
        // first run to rename the handler would have cut them all on the next.
        ExternalTypeinfoResult result = resolveExternalTypeinfo(program, baseFieldAddr);
        if (result != null) {
            if (!typeinfoToClassName.containsKey(result.typeinfoAddr)) {
                typeinfoToClassName.put(result.typeinfoAddr, result.className);
                typeinfoAddresses.add(result.typeinfoAddr);
            }
            typeinfoIn.computeIfAbsent(result.program, k -> new HashMap<>())
                    .putIfAbsent(result.typeinfoAddr, result.className);
            addParentChild(childClassName, result.className, offsetFlags);
            resolveParents(result.program, result.typeinfoAddr, result.className);
            return;
        }
        // A same-module base in a CRO that nothing has labelled: its _ZTS string names it,
        // as ExportClassHierarchy already does. Only after the import record has had its
        // say, since an imported word holds another module's address.
        if (basePtr != 0 && program != this.program) {
            try {
                Address local = program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(basePtr);
                String name = Demangler.classNameOfTypeinfo(program, local);
                if (name != null && !name.startsWith("__cxxabiv1")) {
                    typeinfoIn.computeIfAbsent(program, k -> new HashMap<>())
                            .putIfAbsent(basePtr, name);
                    addParentChild(childClassName, name, offsetFlags);
                    resolveParents(program, basePtr, name);
                    return;
                }
            } catch (Exception e) {
                // Not an address in that module.
            }
        }
        if (basePtr == 0 || isOnUnresolved(basePtr)) {
            script.println("    WARNING: Could not resolve external parent for " +
                    childClassName + " at " + baseFieldAddr);
            return;
        }

        script.println("    WARNING: Unknown base typeinfo pointer 0x" +
                Long.toHexString(basePtr) + " for " + childClassName);
    }

    // ---------------------------------------------------------------
    //  Accessors for the layout pass
    //
    //  Every map here is cleared at the top of run(), so a caller working across
    //  several programs has to copy what it needs before the next run() starts.
    // ---------------------------------------------------------------

    /** Class name -> its bases, with offsets and the virtual flag. */
    public Map<String, List<BaseRef>> getBaseInfo() {
        return baseInfoMap;
    }

    /** Class name -> the function-slot struct of each sub-vtable. */
    public Map<String, List<Structure>> getClassVfuncs() {
        return classVfuncs;
    }

    /** Class name -> the offset-to-top word in front of each sub-vtable's RTTI slot. */
    /**
     * class name -> the sub-tables of its own vtable, with each one's head, offset-to-top
     * and virtual-base offsets. Consumers should read geometry from here rather than
     * recomputing it from an address: a class with virtual bases puts one offset word per
     * virtual base in front of offset-to-top, so no fixed arithmetic works.
     */
    public Map<String, List<VtableScan.SubTable>> getVtableSubTables() {
        return Collections.unmodifiableMap(allVtableSubTables);
    }

    public Map<String, List<Address>> getVtableHeads() {
        return allVtableHeads;
    }

    /** Class name -> the namespace it was found in. */
    public Map<String, Namespace> getClassNamespaces() {
        return classNamespaces;
    }

    private boolean isOnUnresolved(long addr) {
        Address realAddr = program.getMinAddress().getAddressSpace().getAddress(addr);
        Symbol[] syms = symTab.getSymbols(realAddr);
        if (syms != null && syms.length > 0) {
            return syms[0].getName().equals("OnUnresolved");
        }
        return false;
    }

    private void addParentChild(String childName, String parentName, int offsetFlags) {
        parentMap.computeIfAbsent(childName, k -> new ArrayList<>()).add(parentName);
        childrenMap.computeIfAbsent(parentName, k -> new ArrayList<>()).add(childName);
        baseInfoMap.computeIfAbsent(childName, k -> new ArrayList<>())
                .add(new BaseRef(parentName, offsetFlags));
    }

    // ---------------------------------------------------------------
    //  Cross-module resolution
    // ---------------------------------------------------------------

    private static class ExternalTypeinfoResult {
        Program program;
        long typeinfoAddr;
        String className;
    }

    private Program openCroProgram(String progPath) {
        if (importedPrograms.containsKey(progPath)) {
            return importedPrograms.get(progPath);
        }
        try {
            ProjectData projectData = script.getState().getProject().getProjectData();
            DomainFile domainFile = projectData.getFile(progPath);
            if (domainFile == null) {
                script.println("    WARNING: Could not find CRO program: " + progPath);
                importedPrograms.put(progPath, null);
                return null;
            }
            Program prog = (Program) domainFile.getDomainObject(
                    script, true, false, script.getMonitor());
            importedPrograms.put(progPath, prog);
            // Separate catch from the open above. Reading the symbols can throw, and
            // sharing one catch meant the handler overwrote the map entry with null --
            // dropping the only reference to a program this pass is holding a consumer on,
            // so nothing could ever release it.
            try {
                collectTypeinfoSymbols(prog);
            } catch (Exception e) {
                script.println("    WARNING: Could not read typeinfo from " + progPath
                        + ": " + e.getMessage() + " (program stays open until release)");
            }
            return prog;
        } catch (Exception e) {
            script.println("    ERROR: Could not open CRO program " +
                    progPath + ": " + e.getMessage());
            importedPrograms.put(progPath, null);
            return null;
        }
    }

    private ExternalTypeinfoResult resolveExternalTypeinfo(
            Program sourceProgram, Address refAddr) {
        ReferenceManager refMgr = sourceProgram.getReferenceManager();
        Reference[] refs = refMgr.getReferencesFrom(refAddr);

        for (Reference ref : refs) {
            if (!(ref instanceof ExternalReference extRef)) continue;
            ExternalLocation extLoc = extRef.getExternalLocation();

            ExternalManager exMan = sourceProgram.getExternalManager();
            Library imported = exMan.getExternalLibrary(extLoc.getLibraryName());
            if (imported == null) continue;
            String progPath = imported.getAssociatedProgramPath();
            if (progPath == null) continue;

            Program croProg = openCroProgram(progPath);
            if (croProg == null) continue;

            Address extAddr = extLoc.getAddress();
            if (extAddr == null) continue;

            Address croAddr = croProg.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(extAddr.getOffset());

            Symbol[] syms = croProg.getSymbolTable().getSymbols(croAddr);
            for (Symbol sym : syms) {
                if (sym.getName().equals("typeinfo")) {
                    Namespace ns = sym.getParentNamespace();
                    if (ns != null && !ns.isGlobal()) {
                        ExternalTypeinfoResult result = new ExternalTypeinfoResult();
                        result.program = croProg;
                        result.typeinfoAddr = croAddr.getOffset();
                        result.className = ns.getName(true);
                        return result;
                    }
                }
            }

            // Fallback: read name pointer
            try {
                Memory croMem = croProg.getMemory();
                long namePtr = Integer.toUnsignedLong(croMem.getInt(croAddr.add(4)));
                Address namePtrAddr = croProg.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(namePtr);
                Symbol[] nameSyms = croProg.getSymbolTable().getSymbols(namePtrAddr);
                for (Symbol sym : nameSyms) {
                    Namespace ns = sym.getParentNamespace();
                    if (ns != null && !ns.isGlobal()) {
                        ExternalTypeinfoResult result = new ExternalTypeinfoResult();
                        result.program = croProg;
                        result.typeinfoAddr = croAddr.getOffset();
                        result.className = ns.getName(true);
                        return result;
                    }
                }
            } catch (Exception e) {
                script.println("WARNING: Could not read CRO typeinfo at " +
                        croAddr + " in " + progPath);
            }

            // Last: the _ZTS string itself, for a module nothing has labelled yet.
            String fromBytes = Demangler.classNameOfTypeinfo(croProg, croAddr);
            if (fromBytes != null) {
                ExternalTypeinfoResult result = new ExternalTypeinfoResult();
                result.program = croProg;
                result.typeinfoAddr = croAddr.getOffset();
                result.className = fromBytes;
                return result;
            }
        }
        return null;
    }

    // ---------------------------------------------------------------
    //  Name propagation: push child-discovered names up to ancestors
    // ---------------------------------------------------------------

    /** Push a name found at slot N of a descendant onto every ancestor's slot N. */
    private int propagateNames() throws Exception {
        int count = 0;

        AddressSpace addressSpace = program.getMinAddress().getAddressSpace();
        for (String className : processed) {
            List<List<Long>> subVtables = allVtableSlots.get(className);
            List<Address> addressPoints = allVtableAddressPoints.get(className);
            if (subVtables == null || addressPoints == null) continue;

            for (int sub = 0; sub < subVtables.size(); sub++) {
                List<Long> slots = subVtables.get(sub);
                Address base = (sub < addressPoints.size()) ? addressPoints.get(sub) : null;
                if (base == null) continue;

                for (int i = 0; i < slots.size(); i++) {
                    long funcPtr = slots.get(i);
                    if (funcPtr == 0) continue;
                    Address funcAddr = addressSpace.getAddress(funcPtr & ~1L);

                    String name = getNonGenericName(funcAddr);
                    if (name == null) continue;
                    count += propagateToAncestors(className, sub, i, name);
                }
            }
        }

        return count;
    }

    /** A name this pass is free to overwrite: Ghidra's default, or its own placeholder. */
    private static boolean isRenameable(String name) {
        return isAutoLabel(name) || isPlaceholder(name);
    }

    /** Any placeholder handed out by computeSlotNames(): VF02, D1, D0_1 and friends.
     *  F02 too: that was this pass's spelling before the padded VF names, and an
     *  earlier run's output still has to read as ours so it can be revised. */
    private static boolean isPlaceholder(String name) {
        return isSlotPlaceholder(name) || isDestructorPlaceholder(name);
    }


    /** VF02, or VF07_1 in sub-vtable 1. Widened paddings such as VF002 match too. */
    private static boolean isSlotPlaceholder(String name) {
        return SLOT_PLACEHOLDER.matcher(name).matches();
    }

    /** D1, or D0_1 in sub-vtable 1. */
    private static boolean isDestructorPlaceholder(String name) {
        return DTOR_PLACEHOLDER.matcher(name).matches();
    }

    /** A real name for this function, or null if it only carries a default or a placeholder. */
    private String getNonGenericName(Address funcAddr) {
        // A name rejectForeignRecoveredNames could not explain is not a name this pass
        // will spread further, whether or not it was able to delete it.
        if (foreignRecoveredNames.contains(funcAddr.getOffset())) return null;
        if (funcAddr.equals(unresolvedImportHandler) || funcAddr.equals(unresolvedImportTail)) {
            return null;
        }
        for (Symbol s : symTab.getSymbols(funcAddr)) {
            String name = s.getName();
            if (isAutoLabel(name)) continue;
            // The CRO header's entry points, as CRXLibrary labels them. In a CRO every
            // slot that imports its function reads as the module's own OnUnresolved until
            // the loader binds it, so the name turns up on dozens of slots and was being
            // spread up to their code.bin ancestors (DemoActor, script::IRecept) as if it
            // were a method. It is never one.
            if (LOADER_ENTRY_NAMES.contains(name)) continue;
            if (isSlotPlaceholder(name) || isDestructorPlaceholder(name)) continue;
            if (!s.getParentNamespace().isGlobal()) {
                return name;
            }
        }
        return null;
    }

    private int propagateToAncestors(String childClass, int subVtableIdx,
                                     int slotIdx, String name) throws Exception {
        int count = 0;
        List<String> parents = parentMap.get(childClass);
        if (parents == null) return 0;

        for (String parent : parents) {
            count += propagateToAncestor(parent, subVtableIdx, slotIdx, name, new HashSet<>());
        }
        return count;
    }

    private int propagateToAncestor(String ancestor, int subVtableIdx,
                                    int slotIdx, String name,
                                    Set<String> visited) throws Exception {
        if (!visited.add(ancestor)) return 0;
        int count = 0;

        AddressSpace addressSpace = program.getMinAddress().getAddressSpace();
        // Check if this ancestor has the slot in the same sub-vtable
        List<List<Long>> subVtables = allVtableSlots.get(ancestor);
        List<Address> addressPoints = allVtableAddressPoints.get(ancestor);
        if (subVtables != null && addressPoints != null &&
                subVtableIdx < subVtables.size() && subVtableIdx < addressPoints.size()) {

            List<Long> ancestorSlots = subVtables.get(subVtableIdx);
            Address ancestorBase = addressPoints.get(subVtableIdx);

            if (slotIdx < ancestorSlots.size() && ancestorBase != null) {
                long funcPtr = ancestorSlots.get(slotIdx);
                if (funcPtr != 0) {
                    Address funcAddr = addressSpace.getAddress(funcPtr & ~1L);

                    // A lone branch is a real ARMCC function, not a tail call belonging to
                    // something else -- a trivial destructor collapses to exactly this
                    // shape. Undo Ghidra's thunk modelling so it stops showing the
                    // target's name here, then let it be named like any other slot.
                    Function stub = program.getListing().getFunctionAt(funcAddr);
                    if (stub != null && stub.isThunk()) {
                        branchStubsSkipped++;
                        try {
                            stub.setThunkedFunction(null);
                        } catch (Exception e) { /* already plain */ }
                    }

                    // Only rename if the current name is generic
                    String currentName = getNonGenericName(funcAddr);
                    if (currentName == null) {
                        // This slot has a generic name â€” apply the discovered name
                        // For destructors, use the ancestor's own class name
                        String appliedName = name;
                        if (name.startsWith("~")) {
                            String leafName = ancestor;
                            int lastSep = ancestor.lastIndexOf("::");
                            if (lastSep >= 0) {
                                leafName = ancestor.substring(lastSep + 2);
                            }
                            appliedName = "~" + leafName;
                        }

                        SymbolTable symTab = program.getSymbolTable();
                        Symbol[] syms = symTab.getSymbols(funcAddr);
                        if (syms != null && syms.length > 0) {
                            Symbol sym = syms[0];
                            if (sym != null && (sym.getName().startsWith("FUN_") ||
                                    sym.getName().startsWith("thunk_") ||
                                    isSlotPlaceholder(sym.getName()))) {   // never a D0/D1
                                sym.setName(appliedName, SourceType.USER_DEFINED);
                                count++;
                            }
                        }
                    }
                }
            }
        }

        // Continue upward
        List<String> grandparents = parentMap.get(ancestor);
        if (grandparents != null) {
            for (String gp : grandparents) {
                count += propagateToAncestor(gp, subVtableIdx, slotIdx, name, visited);
            }
        }

        return count;
    }

    // ---------------------------------------------------------------
    //  operator delete detection
    // ---------------------------------------------------------------

    /**
     * Turn every vtable slot target into a function, once, up front.
     *
     * @return how many did not exist yet and had to be disassembled and created
     */
    private int ensureVtableFunctions() throws Exception {
        int created = 0;
        AddressSpace space = program.getMinAddress().getAddressSpace();
        for (Map.Entry<String, List<List<Long>>> entry : allVtableSlots.entrySet()) {
            List<Address> points = allVtableAddressPoints.get(entry.getKey());
            List<List<Long>> subVtables = entry.getValue();
            for (int v = 0; v < subVtables.size(); v++) {
                Address base = (points != null && v < points.size()) ? points.get(v) : null;
                List<Long> slots = subVtables.get(v);
                for (int i = 0; i < slots.size(); i++) {
                    long funcPtr = slots.get(i);
                    if (funcPtr == 0) continue;
                    if (base != null && isPureVirtualRef(base.add(4L * i))) continue;

                    Address target = space.getAddress(funcPtr & ~1L);
                    boolean isNew = program.getListing().getFunctionAt(target) == null;
                    if (ensureFunction(target, (funcPtr & 1L) != 0) != null && isNew) {
                        created++;
                    }
                }
            }
        }

        // The loop above walks only the groups a class owns. Construction vtables are
        // skipped for naming -- they deliberately contribute none -- but their slots still
        // point at real functions, and some of those appear nowhere else: a class with no
        // virtual-base sub-table of its own has its destructor thunks only in the _ZT_B1_
        // tables emitted for classes below it. Without a function there, the name has
        // nothing to attach to and lands only in the class dump, which is where the 274
        // slot targets with no function in the symbol export came from.
        if (vtableScan != null) {
            for (VtableScan.VtableGroup group : vtableScan.groups()) {
                if (group.kind() != VtableScan.Kind.CONSTRUCTION) continue;
                for (VtableScan.SubTable sub : group.subs()) {
                    for (long funcPtr : sub.slots()) {
                        if (funcPtr == 0) continue;
                        Address target = space.getAddress(funcPtr & ~1L);
                        if (pureVirtualAddr != 0
                                && target.getOffset() == (pureVirtualAddr & ~1L)) continue;
                        boolean isNew = program.getListing().getFunctionAt(target) == null;
                        if (ensureFunction(target, (funcPtr & 1L) != 0) != null && isNew) {
                            created++;
                        }
                    }
                }
            }
        }
        return created;
    }

    /**
     * Operator delete addresses, from symbols only. Do not try to infer these from
     * what deleting destructors call: teardown runs through a chain of helpers and
     * wrappers, all called by the same classes, so agreement cannot single out the
     * deallocator. Only a tiebreaker anyway â€” writesOwnVtable finds D1 structurally.
     */
    private void collectOperatorDeletes() {
        SymbolIterator named = symTab.getAllSymbols(false);
        List<String> found = new ArrayList<>();
        List<Symbol> stale = new ArrayList<>();
        while (named.hasNext()) {
            Symbol sym = named.next();
            if (!isOperatorDelete(sym.getName()) || sym.isExternal()) continue;
            // A _ZdlPv this pass wrote onto a vtable slot is a leftover from when every
            // agreeing candidate got the label. A deallocator is a free function; the slot
            // it was put on is some class's D0. Reading it back as evidence would keep the
            // mistake alive across runs, so it is removed rather than merely ignored.
            if (sym.getSource() == SourceType.ANALYSIS
                    && !isDeallocatorCandidate(sym.getAddress())) {
                stale.add(sym);
                continue;
            }
            if (operatorDeleteAddrs.add(sym.getAddress().getOffset() & ~1L)) {
                found.add(sym.getName() + " at " + sym.getAddress());
            }
        }
        for (Symbol sym : stale) {
            script.printf("    Dropping stale %s at %s: it is a vtable slot, not a free " +
                    "function\n", sym.getName(), sym.getAddress());
            sym.delete();
        }
        if (found.isEmpty()) {
            script.println("    No operator delete symbol; relying on vtable structure");
        } else {
            script.printf("    operator delete: %s\n", String.join(", ", found));
        }
    }
    // ---------------------------------------------------------------
    //  Mangled name emission
    // ---------------------------------------------------------------

    /**
     * Everything a member function's mangled name says beyond its class: cv-qualifier
     * ({@code K}, {@code V}, {@code r}), the unqualified name, and the parameter list.
     */
    private record Signature(String cv, String name, String params, String source) {
        /** The same member, declared in the class whose {@code _ZTS} is {@code enc}. */
        String spellIn(String enc) {
            String nested;
            if (enc.charAt(0) == 'N') {
                if (enc.charAt(enc.length() - 1) != 'E') return null;
                nested = enc.substring(1, enc.length() - 1);
            } else {
                nested = enc;
            }
            return "_ZN" + cv + nested + name.length() + name + "E" + params;
        }
    }

    /** Qualified method ("Class::name") -> the signature it inherits from a known seed. */
    private final Map<String, Signature> knownSignatures = new HashMap<>();
    private int signatureSeeds = 0;
    private int signaturesInherited = 0;
    /** Recovered method names left as plain labels: their signature is not known. */
    private int methodsLeftUnmangled = 0;

    /**
     * Parse {@code _ZN [rVK]* (St | <len><id>)+ E <params>} -- a member of a plain,
     * non-template class. Anything with a template or a substitution reference in it is
     * refused: splicing that into another class would renumber what the references point
     * at, and a wrong name is worse than a plain label.
     */
    private static Signature parseMemberSignature(String mangled, String source) {
        if (mangled == null || !mangled.startsWith("_ZN")) return null;
        int i = 3;
        int cvStart = i;
        while (i < mangled.length() && "rVK".indexOf(mangled.charAt(i)) >= 0) i++;
        String cv = mangled.substring(cvStart, i);
        String last = null;
        while (i < mangled.length() && mangled.charAt(i) != 'E') {
            if (mangled.startsWith("St", i)) { i += 2; continue; }
            if (!Character.isDigit(mangled.charAt(i))) return null;
            int j = i;
            while (j < mangled.length() && Character.isDigit(mangled.charAt(j))) j++;
            int len = Integer.parseInt(mangled.substring(i, j));
            if (j + len > mangled.length()) return null;
            last = mangled.substring(j, j + len);
            i = j + len;
        }
        if (last == null || i >= mangled.length()) return null;
        String params = mangled.substring(i + 1);
        if (params.isEmpty()) return null;
        // S_, S0_ ... and T_ refer back into the prefix; St/Sa/Ss... are fine.
        if (params.matches(".*(S[0-9A-Z]*_|T[0-9]*_).*")) return null;
        if (!isPlainIdentifier(last)) return null;
        return new Signature(cv, last, params, mangled);
    }

    /**
     * The base whose vtable this class's primary table extends: the first base, when it is
     * non-virtual and at offset 0. Null otherwise -- slot indices only line up along this
     * chain.
     */
    private String primaryBase(String className) {
        List<BaseRef> bases = baseInfoMap.get(className);
        if (bases == null || bases.isEmpty()) return null;
        BaseRef b = bases.get(0);
        if (b.isVirtual() || b.offset() != 0) return null;
        return b.name();
    }

    /**
     * Seed from every slot target that carries a real symbol, then hand each seed's
     * signature to the overriders at the same slot down the primary-base chain.
     *
     * <p>A mangled name is a claim about the declaration: class, name, parameters and
     * cv-qualifiers. A vtable gives the first two. The other two are known only where a
     * real symbol says so -- a module export, which CRXLibrary now keeps verbatim -- and
     * wherever C++ forces them to be the same: an override has exactly the parameter
     * list and cv-qualifiers of what it overrides. So {@code _ZNKSt9exception4whatEv}
     * makes every overrider of {@code what} a {@code _ZNK<cls>4whatEv}, K included.
     * Only the primary sub-table is followed; a secondary one's slot index is not the
     * base's.
     */
    private void collectKnownSignatures() {
        knownSignatures.clear();
        AddressSpace space = program.getMinAddress().getAddressSpace();
        // class -> slot index -> seed found at that class's own slot
        Map<String, Map<Integer, Signature>> seedAt = new HashMap<>();
        for (Map.Entry<String, List<Long>> e : vtableSlots.entrySet()) {
            List<Long> slots = e.getValue();
            for (int i = 0; i < slots.size(); i++) {
                long ptr = slots.get(i);
                if (ptr == 0) continue;
                Address at = space.getAddress(ptr & ~1L);
                for (Symbol s : symTab.getSymbols(at)) {
                    if (s.getSource() != SourceType.IMPORTED) continue;
                    Signature sig = parseMemberSignature(s.getName(), s.getName());
                    if (sig == null) continue;
                    seedAt.computeIfAbsent(e.getKey(), k -> new HashMap<>()).put(i, sig);
                    break;
                }
            }
        }
        for (Map<Integer, Signature> m : seedAt.values()) signatureSeeds += m.size();
        if (seedAt.isEmpty()) return;

        // Up as well as down. What an override overrides has the same parameters and
        // cv-qualifiers, so a seed fixes the whole slot, not just the classes below it:
        // _ZNKSt14__rw_exception4whatEv is what spells std::exception::what, which no
        // symbol source names directly.
        for (Map.Entry<String, Map<Integer, Signature>> e :
                new ArrayList<>(seedAt.entrySet())) {
            for (Map.Entry<Integer, Signature> s : new ArrayList<>(e.getValue().entrySet())) {
                int i = s.getKey();
                Set<String> seen = new HashSet<>();
                for (String c = primaryBase(e.getKey()); c != null && seen.add(c);
                     c = primaryBase(c)) {
                    List<Long> ps = vtableSlots.get(c);
                    if (ps == null || ps.size() <= i) break;
                    seedAt.computeIfAbsent(c, k -> new HashMap<>()).putIfAbsent(i, s.getValue());
                }
            }
        }

        for (Map.Entry<String, List<Long>> e : vtableSlots.entrySet()) {
            List<Long> slots = e.getValue();
            for (int i = 0; i < slots.size(); i++) {
                long ptr = slots.get(i);
                if (ptr == 0) continue;
                Signature sig = null;
                // The class itself, then its primary base, then that one's, ...
                Set<String> seen = new HashSet<>();
                for (String c = e.getKey(); c != null && seen.add(c); ) {
                    Map<Integer, Signature> m = seedAt.get(c);
                    if (m != null && m.containsKey(i)) { sig = m.get(i); break; }
                    String p = primaryBase(c);
                    List<Long> ps = (p == null) ? null : vtableSlots.get(p);
                    if (ps == null || ps.size() <= i) break;
                    c = p;
                }
                if (sig == null) continue;
                Address at = space.getAddress(ptr & ~1L);
                for (Symbol s : symTab.getSymbols(at)) {
                    if (s.getParentNamespace().isGlobal()) continue;
                    if (!s.getName().equals(sig.name())) continue;
                    String key = s.getParentNamespace().getName(true) + "::" + sig.name();
                    if (knownSignatures.putIfAbsent(key, sig) == null) signaturesInherited++;
                }
            }
        }
    }

    /**
     * Add each vtable function's Itanium-mangled spelling as a second label, for
     * ToggleMangledNames and ExportSymbols. Parameters are unknown this early, so
     * everything is mangled as taking void.
     */
    private int emitMangledNames() throws Exception {
        AddressSpace addressSpace = program.getMinAddress().getAddressSpace();
        Set<Address> seen = new HashSet<>();
        mangledPlans.clear();
        ambiguousMangled.clear();
        collectKnownSignatures();

        // Pass 1: work out every name without writing any of it, so a name that lands on
        // two addresses can be spotted before either is committed.
        Map<String, List<Address>> byName = new HashMap<>();
        for (String className : processed) {
            List<List<Long>> subVtables = allVtableSlots.get(className);
            if (subVtables == null) continue;
            for (List<Long> slots : subVtables) {
                for (long funcPtr : slots) {
                    if (funcPtr == 0) continue;
                    Address funcAddr = addressSpace.getAddress(funcPtr & ~1L);
                    if (!seen.add(funcAddr)) continue;
                    MangledPlan plan = planMangledName(funcAddr);
                    if (plan == null) continue;
                    mangledPlans.put(funcAddr, plan);
                    if (plan.mangled() != null) {
                        byName.computeIfAbsent(plan.mangled(), k -> new ArrayList<>())
                                .add(funcAddr);
                    }
                }
            }
        }
        // The slots of a class with no table of its own, which the loop above cannot
        // reach: it walks allVtableSlots, and a construction-only class has no entry
        // there. Without this its destructors came out as bare D1/D0 labels with no
        // mangled spelling beside them -- nn::fs::IInputStream, IStream and AcObjectBase
        // were named by nameConstructionOnlyClasses and then left unmangled.
        for (Address funcAddr : constructionOnlyAddrs) {
            if (!seen.add(funcAddr)) continue;
            MangledPlan plan = planMangledName(funcAddr);
            if (plan == null) continue;
            mangledPlans.put(funcAddr, plan);
            if (plan.mangled() != null) {
                byName.computeIfAbsent(plan.mangled(), k -> new ArrayList<>()).add(funcAddr);
            }
        }
        for (Map.Entry<String, List<Address>> e : byName.entrySet()) {
            if (e.getValue().size() > 1) ambiguousMangled.add(e.getKey());
        }

        // Pass 2: write.
        int count = 0;
        for (Address funcAddr : mangledPlans.keySet()) {
            if (emitMangledName(funcAddr)) count++;
        }

        if (!ambiguousMangled.isEmpty()) {
            script.printf("    Name conflicts:         %d mangled names would have landed " +
                    "on more than one address (%d symbols); none written\n",
                    ambiguousMangled.size(), mangledNamesSuppressed);
            int shown = 0;
            for (Map.Entry<String, List<Address>> e : byName.entrySet()) {
                if (e.getValue().size() < 2 || shown++ >= 8) continue;
                script.printf("                            %s at %s\n", e.getKey(),
                        e.getValue());
            }
        }
        return count;
    }

    /**
     * Add the _ZTV spelling beside each class's "vtable" label. Only the primary head gets
     * one: _ZTV names the whole vtable object, so the secondary sub-vtables inside it have
     * no symbol of their own.
     */
    private int emitMangledVtableNames() {
        int count = 0;
        for (String className : processed) {
            Namespace ns = classNamespaces.get(className);
            if (ns == null) continue;
            // The same address processClass labels "vtable": the head, not the address point
            Address head = vtableHeads.getOrDefault(className,
                    vtableAddressPoints.get(className));
            if (head == null) continue;

            String enc = typeNameEncoding(className, ns);
            if (enc == null) continue;
            if (MangledNames.addMangled(script, program, head, "_ZTV" + enc)) count++;
        }
        return count;
    }

    /**
     * Label the VTTs and the construction vtables ARMCC emitted, which until now were
     * indistinguishable from extra sub-vtables of whichever class's typeinfo they carry.
     *
     * <p>The zero-size {@code _ZTV<Class>} alias the compiler also puts on a VTT is
     * deliberately not reproduced: it exists only to trap tools that resolve a vtable by
     * name and take the first hit.
     */
    private int emitVttAndConstructionNames() {
        if (vtableScan == null) return 0;
        int count = 0;

        for (VtableScan.Vtt vtt : vtableScan.vtts()) {
            Namespace ns = classNamespaces.get(vtt.ownerClass());
            if (ns == null) continue;
            try {
                symTab.createLabel(vtt.start(), "VTT", ns, SourceType.USER_DEFINED);
            } catch (Exception e) {
                script.println("    WARNING: could not label VTT at " + vtt.start());
            }
            String enc = typeNameEncoding(vtt.ownerClass(), ns);
            if (enc != null && MangledNames.addMangled(script, program, vtt.start(),
                    "_ZTT" + enc)) {
                count++;
            }
            applyVttArray(vtt);
        }

        // How deep each deriving class's construction run goes. ARMCC emits one C table
        // per class on the chain from the base up to the owner -- C1..CN, then B1_N..B1_1
        // back out -- so the number of C tables attributed to one owner is that chain's
        // depth. AcFsFdShadow has three (AcFishFieldBase, AcFishCommon, AcObjectBase).
        Map<String, Integer> chainDepth = new HashMap<>();
        for (VtableScan.VtableGroup group : vtableScan.groups()) {
            if (group.kind() != VtableScan.Kind.CONSTRUCTION) continue;
            if (group.derivedOwner() == null) continue;
            if (group.primary().offsetToTop() != 0) continue;
            chainDepth.merge(group.derivedOwner(), 1, Integer::sum);
        }

        // Work every name out before writing any, so one that would land on two addresses
        // can be dropped. _ZT_B1_14ObjectResource1_15AcFishFieldBase12AcFsFdShadow was
        // appearing at both 0x83e558 and 0x83e5b8: the normalised spelling cannot tell two
        // tables of one chain apart, which is precisely what the depth field is for.
        Map<String, List<VtableScan.VtableGroup>> byName = new LinkedHashMap<>();
        Map<VtableScan.VtableGroup, String> chosen = new HashMap<>();
        for (VtableScan.VtableGroup group : vtableScan.groups()) {
            if (group.kind() != VtableScan.Kind.CONSTRUCTION) continue;
            if (group.derivedOwner() == null) continue;
            String name = constructionMangledName(group);
            if (name == null) continue;
            chosen.put(group, name);
            byName.computeIfAbsent(name, k -> new ArrayList<>()).add(group);
        }
        for (Map.Entry<String, List<VtableScan.VtableGroup>> e : byName.entrySet()) {
            if (e.getValue().size() > 1) {
                for (VtableScan.VtableGroup g : e.getValue()) chosen.remove(g);
                ctorNameAmbiguous++;
                if (ctorAmbiguousExamples.size() < 5) {
                    StringBuilder sb = new StringBuilder(e.getKey() + " at");
                    for (VtableScan.VtableGroup g : e.getValue()) {
                        sb.append(' ').append(g.head()).append(" (").append(g.className())
                                .append(" for ").append(g.derivedOwner()).append(", ott ")
                                .append(g.primary().offsetToTop()).append(')');
                    }
                    ctorAmbiguousExamples.add(sb.toString());
                }
            }
        }

        for (VtableScan.VtableGroup group : vtableScan.groups()) {
            if (group.kind() != VtableScan.Kind.CONSTRUCTION) continue;
            String derived = group.derivedOwner();
            if (derived == null) continue;

            Namespace baseNs = classNamespaces.get(group.className());
            if (baseNs == null) baseNs = namespaceForForeignClass(group.className());
            Namespace derivedNs = classNamespaces.get(derived);
            if (derivedNs == null) derivedNs = namespaceForForeignClass(derived);
            if (baseNs == null || derivedNs == null) continue;

            String baseEnc = typeNameEncoding(group.className(), baseNs);
            String derivedEnc = typeNameEncoding(derived, derivedNs);
            if (baseEnc == null || derivedEnc == null) continue;

            // ARMCC's own forms, not Itanium's _ZTC: _ZT_C<depth>_<path> for a construction
            // table, _ZT_B1_<VBase><depth>_<path> for the virtual-base one. Both are
            // written in their *normalised* shape -- depth 1 and a two-class path -- which
            // is how ACNL's own labels spell them. The true depth and the full path are not
            // recoverable from the image, so nothing here tries to reconstruct them.
            //
            // The two are separate objects, emitted C1..CN then B1_N..B1_1, so a C table
            // and its matching B table are adjacent only at the middle of that run. Which
            // one a group is, is a property of the table: a C table starts at
            // offset-to-top 0 like any vtable, a B table starts negative because it
            // describes a virtual base subobject that sits at the top of nothing. Asking
            // instead whether the typeinfo class is a virtual base of the derived class --
            // as this once did -- asks about the wrong class entirely: the virtual base is
            // a third class again, so the test was false every time and _ZT_B1_ never
            // appeared on any of the 58 construction tables here.
            // A C table is the one at offset-to-top 0; B tables may be negative *or*
            // positive, since a shared virtual base can sit before the subobject being
            // built (armcc probe Q3).
            boolean vbaseTable = group.primary().offsetToTop() != 0;
            String mangled = chosen.get(group);
            List<String> chain = derivationChain(group.className(), derived);
            int depth = (chain == null) ? 0 : chain.size() - 1;

            // No demangler in Ghidra knows either form -- they are not _ZTC/_ZTB -- so a
            // readable label has to be written here or the address stays anonymous. It goes
            // in the *deriving* class's namespace, since that is whose data this is; the
            // typeinfo it carries belonging to the base is the confusion these labels end.
            String label = (vbaseTable ? "construction_vtable_vbase_for_"
                                       : "construction_vtable_for_")
                    + flatten(baseNs, group.className())
                    + ((depth > 1) ? "_depth" + depth : "");
            try {
                symTab.createLabel(group.head(), label, derivedNs, SourceType.USER_DEFINED);
            } catch (Exception e) {
                script.println("    WARNING: could not label " + label + " at " + group.head());
            }

            if (mangled != null
                    && MangledNames.addMangled(script, program, group.head(), mangled)) {
                count++;
            }
        }
        return count;
    }

    /**
     * The armcc spelling for one construction vtable, or null when none can be written.
     *
     * <p>Only a depth-1 chain gets a mangled name. ARMCC spells deeper ones
     * {@code _ZT_C<depth>_<path>} with the path running base-first through every
     * intermediate class, and neither the VTT entry order for depth > 1 nor the diamond
     * case has been probed against a real compiler. Writing {@code _ZT_C1_<base><derived>}
     * for a depth-3 table would claim to be armcc's symbol while being demonstrably not
     * it, and it is also not unique -- two tables of one chain normalise to the same
     * string, which is how one name ended up at two addresses.
     */
    private String constructionMangledName(VtableScan.VtableGroup group) {
        String derived = group.derivedOwner();
        // The path runs from the table's own class through every intermediate class to the
        // most-derived one, and the depth is the number of edges along it. The normalised
        // depth-1 spelling this used to write was both wrong for a deeper chain and not
        // unique -- two tables of one chain collapsed onto the same string.
        List<String> path = derivationChain(group.className(), derived);
        if (path == null || path.size() < 2) {
            ctorDepthUnnamed++;
            if (ctorAmbiguousExamples.size() < 10) {
                ctorAmbiguousExamples.add("no path from " + group.className() + " to "
                        + derived + " (table at " + group.head() + ")");
            }
            return null;
        }
        int depth = path.size() - 1;

        if (group.primary().offsetToTop() == 0) {
            List<String> enc = encodeRun(path);
            if (enc == null) { ctorSubstitutionUnnamed++; return null; }
            return "_ZT_C" + depth + "_" + String.join("", enc);
        }
        // A B table leads with the subobject it describes -- usually the virtual base, but
        // it can be a plain secondary base -- then the depth and path of the C table it
        // belongs to. Without a name for that class there is no honest spelling; the
        // readable label still lands either way.
        String secondary = secondaryBaseFor(group);
        // The leading class is often from another module -- ObjectResource, a code.bin
        // class, leads 251 of ModuleMusFish's B tables -- and a namespace is all the
        // encoding needs, so it is made here as it is for a foreign slot owner.
        if (secondary != null && classNamespaces.get(secondary) == null) {
            namespaceForForeignClass(secondary);
        }
        if (secondary == null || classNamespaces.get(secondary) == null) {
            ctorVbaseUnnamed++;
            if (ctorVbaseExamples.size() < 6) {
                ctorVbaseExamples.add(String.format("%s (for %s) at %s, offset-to-top %d: "
                        + "leading class %s, virtual bases reachable %s", group.className(),
                        group.derivedOwner(), group.head(), group.primary().offsetToTop(),
                        secondary == null ? "none" : secondary + " (no namespace here)",
                        virtualBasesOf(group.className())));
            }
            return null;
        }
        // The leading class shares the substitution run with the path, so the two are
        // encoded together: armcc writes
        // _ZT_B1_N2nn2fs13IPositionableE1_NS0_13IOutputStreamENS0_7IStreamE, where the
        // path's first component back-references the namespace the *leading* class already
        // spelled. Encoding them separately restarts the table and loses that.
        List<String> run = new ArrayList<>();
        run.add(secondary);
        run.addAll(path);
        List<String> enc = encodeRun(run);
        if (enc == null) { ctorSubstitutionUnnamed++; return null; }
        // The literal "B1" never varied across the probes, even with two secondaries in
        // one group, so it is not an index; it is emitted verbatim.
        return "_ZT_B1_" + enc.get(0) + depth + "_"
                + String.join("", enc.subList(1, enc.size()));
    }

    /**
     * Which base subobject a B table describes, which is the class its name leads with.
     *
     * <p>Usually the virtual base, but not always: {@code AcFishFieldBase} has two B
     * tables at depth 1, one led by {@code ObjectResource} (virtual) and one by
     * {@code ResourceGetSkeletal} (a plain secondary base). Asking only for the virtual
     * base would put the same leading class on both and collapse them onto one name.
     *
     * <p>A non-virtual base is identified by offset: the table's offset-to-top is the
     * negative of where that subobject sits. A virtual base's {@code __offset_flags}
     * offset is a position inside the vtable rather than a subobject offset, so it cannot
     * be matched the same way and falls back to the sole-virtual-base closure.
     */
    private String secondaryBaseFor(VtableScan.VtableGroup group) {
        int want = -group.primary().offsetToTop();
        List<BaseRef> bases = baseInfoMap.get(group.className());
        if (bases != null) {
            String match = null;
            for (BaseRef b : bases) {
                if (b.isVirtual() || b.offset() != want) continue;
                if (match != null && !match.equals(b.name())) return null;   // ambiguous
                match = b.name();
            }
            if (match != null) return match;
        }
        // A plain secondary base need not be a direct one: River's +208 ResourceGetSkeletal
        // comes through AcFishMuseumBase. Missing it sent both of River's B tables to the
        // virtual base below, one name for two tables, and both were dropped (29 in MusFish).
        String deep = nonVirtualBaseAt(group.className(), want, 0, 0);
        if (deep != null) return deep;
        return declaredVirtualBase(group.className());
    }

    /**
     * Every slot target of every table -- own, weak, construction, whichever group a class
     * kept -- is a function entry. The naming walks only visit the groups they name from,
     * so a group left out of them (AcFsMuDefault's second group in ModuleMusFish, holding
     * the thunks at 0x1aef8 and 0x1af20) left its targets undecoded bytes with no row.
     */
    private int ensureAllSlotTargetsAreFunctions() {
        if (vtableScan == null) return 0;
        int made = 0;
        for (VtableScan.VtableGroup group : vtableScan.groups()) {
            for (VtableScan.SubTable sub : group.subs()) {
                for (long raw : sub.slots()) {
                    if (raw == 0) continue;
                    if (pureVirtualAddr != 0 && (raw & ~1L) == (pureVirtualAddr & ~1L)) continue;
                    Address a = toAddress(raw & ~1L);
                    MemoryBlock b = mem.getBlock(a);
                    if (b == null || !b.isExecute()) continue;
                    if (program.getFunctionManager().getFunctionAt(a) != null) continue;
                    if (ensureFunction(a, (raw & 1L) != 0) != null) made++;
                }
            }
        }
        return made;
    }

    /**
     * In a module the loader relocates (a CRO), every read-only word the loader rewrote to
     * point into .text is a code pointer -- a vtable slot, a member-function-pointer table
     * entry, a callback table -- and so names a function entry. Ghidra follows none of the
     * non-vtable ones: 1,191 such targets across the CROs had no function and no row
     * (AmiiboCamera 0x144c8 -> 0x4b7c, undecoded). A target that already falls inside a
     * function body is left alone, so a stray pointer cannot split a known function.
     * Nothing happens in an image whose read-only data matches its file (code.bin), where
     * a word's value alone cannot say it is a pointer.
     */
    private int ensureRelocatedCodePointersAreFunctions() {
        int made = 0;
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || block.isExecute()) continue;
            for (MemoryBlockSourceInfo info : block.getSourceInfos()) {
                if (info.getFileBytes().isEmpty()) continue;
                FileBytes fb = info.getFileBytes().get();
                int len = (int) Math.min(info.getLength(), Integer.MAX_VALUE);
                byte[] now = new byte[len];
                byte[] file = new byte[len];
                try {
                    mem.getBytes(info.getMinAddress(), now);
                    fb.getOriginalBytes(info.getFileBytesOffset(), file);
                } catch (Exception e) {
                    continue;
                }
                long base = info.getMinAddress().getOffset();
                for (int i = 0; i + 4 <= len; i += 4) {
                    long v = (now[i] & 0xffL) | (now[i + 1] & 0xffL) << 8
                            | (now[i + 2] & 0xffL) << 16 | (now[i + 3] & 0xffL) << 24;
                    long f = (file[i] & 0xffL) | (file[i + 1] & 0xffL) << 8
                            | (file[i + 2] & 0xffL) << 16 | (file[i + 3] & 0xffL) << 24;
                    if (v == f || v == 0) continue;             // not relocated
                    boolean thumb = (v & 1L) != 0;
                    if (!thumb && (v & 3L) != 0) continue;       // not an ARM entry
                    Address t = toAddress(v & ~1L);
                    MemoryBlock tb = mem.getBlock(t);
                    if (tb == null || !tb.isExecute()) continue;
                    // Inside a host's own contiguous run: leave it. Inside a *detached* range
                    // of some body it is foreign code the host flowed into (armcc functions
                    // are contiguous) -- Downtown's D0 at 0xcddc sat in FUN_0000c070 as a
                    // Thumb-decoded range [0xcdda, 0xcde9] -- and ensureFunction cuts it out.
                    Function host = program.getFunctionManager().getFunctionContaining(t);
                    if (host != null) {
                        AddressRange held = host.getBody().getRangeContaining(t);
                        AddressRange own = host.getBody().getRangeContaining(host.getEntryPoint());
                        if (held == null || held.equals(own)) continue;
                    }
                    if (program.getFunctionManager().getFunctionAt(t) != null) continue;
                    if (ensureFunction(t, thumb) != null) made++;
                }
            }
        }
        return made;
    }

    /** Set while the construction-only pass names a class from its own C table. */
    private boolean namingFromCTable = false;

    private boolean hasConstructionCTable(String cls) {
        if (vtableScan == null) return false;
        for (VtableScan.VtableGroup g : vtableScan.groups()) {
            if (g.kind() == VtableScan.Kind.CONSTRUCTION && cls.equals(g.className())
                    && g.primary().offsetToTop() == 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * The class whose subobject sits at byte {@code want} of {@code cls}, through non-virtual
     * bases only, offsets summed along the way; null when none or more than one.
     */
    private String nonVirtualBaseAt(String cls, int want, int at, int depth) {
        if (depth > 16) return null;
        String found = null;
        for (BaseRef b : baseInfoMap.getOrDefault(cls, List.of())) {
            if (b.isVirtual()) continue;
            int here = at + b.offset();
            String hit = (here == want) ? b.name() : nonVirtualBaseAt(b.name(), want, here, depth + 1);
            if (hit == null) continue;
            if (found != null && !found.equals(hit)) return null;
            found = hit;
        }
        return found;
    }

    /**
     * The chain of direct base relationships from {@code from} down to {@code to},
     * {@code from} first, or null when there is none.
     *
     * <p>{@code AcObjectBase} to {@code AcFsFdShadow} gives
     * {@code [AcObjectBase, AcFishCommon, AcFishFieldBase, AcFsFdShadow]}, which is depth 3
     * and exactly the path armcc spells in {@code _ZT_C3_}.
     */
    private List<String> derivationChain(String from, String to) {
        if (from == null || to == null) return null;
        if (from.equals(to)) return List.of(from);

        // Walk upward from the derived class, remembering who led to each class, then read
        // the route back down. Upward is the direction the graph is stored in.
        Map<String, String> cameFrom = new HashMap<>();
        Deque<String> queue = new ArrayDeque<>();
        queue.add(to);
        cameFrom.put(to, null);
        while (!queue.isEmpty()) {
            String current = queue.poll();
            if (current.equals(from)) {
                List<String> path = new ArrayList<>();
                for (String c = from; c != null; c = cameFrom.get(c)) path.add(c);
                return path;
            }
            List<String> parents = parentMap.get(current);
            if (parents == null) continue;
            for (String parent : parents) {
                if (cameFrom.containsKey(parent)) continue;
                cameFrom.put(parent, current);
                queue.add(parent);
            }
        }
        return null;
    }

    /**
     * The path as one run of Itanium type names, or null when substitutions would be
     * needed.
     *
     * <p>ARMCC mangles the whole path as a single sequence sharing one substitution table,
     * so a second class in an already-named namespace comes out as {@code NS0_7IStreamE}
     * rather than repeating {@code N2nn2fsE}. Concatenating the components independently
     * is correct only while at most one of them is namespaced, which covers almost all of
     * ACNL; the rest are reported rather than spelled wrongly.
     */
    private List<String> encodeRun(List<String> classes) {
        List<String> plain = new ArrayList<>();
        int namespaced = 0;
        for (String cls : classes) {
            Namespace ns = classNamespaces.get(cls);
            // A path through a class from another module (AcObjectBase, in code.bin, under
            // every fish-museum table) needs only its name to be spelled.
            if (ns == null) ns = namespaceForForeignClass(cls);
            if (ns == null) return null;
            String enc = typeNameEncoding(cls, ns);
            if (enc == null) return null;
            if (enc.startsWith("N")) namespaced++;
            plain.add(enc);
        }
        // With at most one nested name there is nothing a later component could refer
        // back to, so the components stand alone and are already correct.
        if (namespaced <= 1) return plain;
        if (namespaced != classes.size()) return null;   // mixed; see substitutedPath
        return substitutedPath(classes);
    }

    /**
     * A path of nested names, mangled as armcc mangles it: one substitution table shared
     * across the whole run.
     *
     * <p>ARMCC treats the path as a single sequence of types rather than independent
     * names, so a namespace already spelled once comes back as a numbered reference:
     * {@code _ZT_C2_N2nn2fs12IInputStreamENS0_7IStreamENS0_10FileStreamE}, where
     * {@code S0_} is {@code nn::fs}. Spelling each component from scratch gives a string
     * armcc would never emit.
     *
     * <p>Candidates accumulate in order of first appearance, one per prefix of each nested
     * name, and are referenced {@code S_}, {@code S0_}, {@code S1_} … So the first name
     * above registers {@code nn}, {@code nn::fs} and {@code nn::fs::IInputStream} as
     * substitutions 0, 1 and 2, and the second reuses number 1 as {@code S0_}.
     *
     * <p>Only paths where <em>every</em> class is nested are handled. Whether an
     * unqualified name also consumes a substitution slot decides the numbering for
     * everything after it, and that has not been measured -- guessing it would silently
     * shift every later index.
     */
    private List<String> substitutedPath(List<String> path) {
        List<String> table = new ArrayList<>();
        List<String> encoded = new ArrayList<>();

        for (String cls : path) {
            StringBuilder out = new StringBuilder();
            List<String> parts = namespaceParts(cls);
            if (parts == null || parts.size() < 2) return null;

            // The longest already-seen prefix wins; anything shorter would still be
            // correct Itanium but is not what the compiler emits.
            int matched = 0;
            int subIndex = -1;
            for (int k = 1; k < parts.size(); k++) {
                int idx = table.indexOf(String.join("::", parts.subList(0, k)));
                if (idx >= 0) { matched = k; subIndex = idx; }
            }

            out.append('N');
            if (subIndex >= 0) {
                out.append('S');
                if (subIndex > 0) out.append(subIndex - 1);
                out.append('_');
            }
            for (int i = matched; i < parts.size(); i++) {
                out.append(parts.get(i).length()).append(parts.get(i));
            }
            out.append('E');

            for (int k = Math.max(matched, 1); k <= parts.size(); k++) {
                String prefix = String.join("::", parts.subList(0, k));
                if (!table.contains(prefix)) table.add(prefix);
            }
            encoded.add(out.toString());
        }
        return encoded;
    }

    /** A class's namespace chain as plain identifiers, or null if any part is not one. */
    private List<String> namespaceParts(String className) {
        Namespace ns = classNamespaces.get(className);
        if (ns == null) return null;
        List<String> parts = new ArrayList<>();
        for (Namespace n = ns; n != null && !n.isGlobal(); n = n.getParentNamespace()) {
            if (!isPlainIdentifier(n.getName())) return null;
            parts.addFirst(n.getName());
        }
        return parts.isEmpty() ? null : parts;
    }

    /**
     * Type a VTT as the array of pointers it is.
     *
     * <p>Without this the entries stay {@code undefined4}, which is why only the first one
     * of each VTT showed a target: Ghidra guesses a reference for a lone undefined word and
     * gives up on the rest, so a five-entry VTT reads as one pointer followed by sixteen
     * loose bytes. Typing the whole run makes every entry carry a reference, which is what
     * puts the construction vtables on the graph -- and a constructor reads them as
     * {@code vtt[i]}, so an array is also the shape the decompiler wants.
     */
    private void applyVttArray(VtableScan.Vtt vtt) {
        int entries = vtt.entries().size();
        if (entries == 0) return;
        Address end = vtt.start().add((long) PTR_SIZE * entries - 1);
        try {
            ArrayDataType arr = new ArrayDataType(PointerDataType.dataType, entries, PTR_SIZE);
            program.getListing().clearCodeUnits(vtt.start(), end, true);
            program.getListing().createData(vtt.start(), arr);
        } catch (Exception e) {
            script.println("    WARNING: could not type the VTT at " + vtt.start());
        }
    }

    /**
     * A class's fully-qualified name with the scope separators flattened, for use inside a
     * label or a data type name. Prefers the namespace, so it spells a class the same way
     * {@link #buildVtableStructs} does.
     */
    private static String flatten(Namespace ns, String fallback) {
        String name = (ns != null) ? ns.getName(true) : fallback;
        return name.replace("::", "_");
    }

    /**
     * The virtual base a {@code _ZT_B1_} table describes, read off the typeinfo of the
     * class whose typeinfo that table carries.
     *
     * <p>{@code _ZT_B1_14ObjectResource1_12AcObjectBase14AcInsectCommon} sits under
     * {@code _ZTI12AcObjectBase}, and {@code AcObjectBase}'s typeinfo is a {@code __vmi}
     * naming {@code ObjectResource} with the virtual bit set. So the name is already
     * written down one edge away -- no need to turn the table's {@code -offsetToTop} back
     * into a class, which is not soundly possible here anyway: {@code __offset_flags}
     * points at a vbase-offset word in the vtable of whichever class declared the virtual
     * base, and for an inherited one that is a different vtable with a different run width
     * and a different offset.
     *
     * <p>The whole base closure is searched, not just the direct edges. Only the class that
     * declares the virtual base names it directly; every class below inherits it, and ARMCC
     * emits a {@code _ZT_B1_} table under each of them too. Looking only one edge up named
     * the 16 tables sitting under {@code AcObjectBase} and left the 18 under
     * {@code AcFishCommon}, {@code AcFishFieldBase} and the rest unnamed.
     *
     * <p>This is the same rule {@link VtableScan} sizes the vcall run with, so a table that
     * gets a header gets a name.
     */
    private final List<String> ctorVbaseExamples = new ArrayList<>();
    private final List<String> ctorAmbiguousExamples = new ArrayList<>();

    /** Every virtual base anywhere above the class, with the class that declares it. */
    private List<String> virtualBasesOf(String cls) {
        List<String> out = new ArrayList<>();
        Set<String> visited = new HashSet<>(List.of(cls));
        Deque<String> work = new ArrayDeque<>(List.of(cls));
        while (!work.isEmpty()) {
            String c = work.poll();
            for (BaseRef b : baseInfoMap.getOrDefault(c, List.of())) {
                if (b.isVirtual()) out.add(b.name() + "<-" + c);
                if (visited.add(b.name())) work.add(b.name());
            }
        }
        return out;
    }

    private String declaredVirtualBase(String typeinfoClass) {
        Set<String> found = new HashSet<>();
        Set<String> visited = new HashSet<>();
        Deque<String> work = new ArrayDeque<>();
        work.add(typeinfoClass);
        visited.add(typeinfoClass);
        while (!work.isEmpty()) {
            for (BaseRef b : baseInfoMap.getOrDefault(work.poll(), List.of())) {
                if (b.isVirtual()) found.add(b.name());
                if (visited.add(b.name())) work.add(b.name());
            }
        }
        return (found.size() == 1) ? found.iterator().next() : null;
    }

    /** A class's Itanium {@code <name>}: the compiler's own _ZTS spelling when there is one. */
    private String typeNameEncoding(String className, Namespace ns) {
        String enc = MangledNames.typeNameFromTypeinfo(program,
                classTypeinfoAddrs.get(className));
        return (enc != null) ? enc : mangleTypeName(ns);
    }

    /**
     * What {@link #emitMangledName} would write, worked out without writing it.
     *
     * @param mangled the name, or null when nothing should be written and any stale
     *                symbol from a previous run should simply be removed
     */
    private record MangledPlan(String mangled, Symbol stale, boolean virtualThunk) {}

    /** Address -> its plan, computed once so the counters inside are not double-counted. */
    private final Map<Address, MangledPlan> mangledPlans = new HashMap<>();

    /** Mangled names that came out for more than one address, so none of them is written. */
    private final Set<String> ambiguousMangled = new HashSet<>();
    private int mangledNamesSuppressed = 0;

    private boolean emitMangledName(Address funcAddr) {
        MangledPlan plan = mangledPlans.get(funcAddr);
        if (plan == null) return false;

        if (plan.mangled() == null) {
            if (plan.stale() != null) plan.stale().delete();
            return false;
        }
        // In armcc output a symbol name has exactly one address. Several names may share
        // one address -- D1 and D2 of a class without virtual bases are literally the same
        // function -- but one name never spreads across addresses. When it would, one of
        // the two derivations is wrong and there is no way to tell which, so neither is
        // written and both are reported. Suffixing with the address, which is what this
        // used to do, produces a symbol armcc could not have emitted and buries the
        // contradiction instead of surfacing it.
        if (ambiguousMangled.contains(plan.mangled())) {
            if (plan.stale() != null) plan.stale().delete();
            mangledNamesSuppressed++;
            return false;
        }
        if (plan.stale() != null) {
            if (plan.stale().getName().equals(plan.mangled())) return false;
            plan.stale().delete();
        }
        try {
            symTab.createLabel(funcAddr, plan.mangled(), program.getGlobalNamespace(),
                    SourceType.ANALYSIS);
            if (plan.virtualThunk()) virtualThunkCount++;
            return true;
        } catch (Exception e) {
            script.println("WARNING: Could not label " + plan.mangled() + " at " + funcAddr);
            return false;
        }
    }

    private MangledPlan planMangledName(Address funcAddr) {
        // A thunk reports the name of what it forwards to, so mangling it here would
        // stamp the target's symbol onto the wrong address.
        Function func = program.getListing().getFunctionAt(funcAddr);
        if (func != null && func.isThunk()) return null;
        // Mangling a name that no referencing table's class can explain would dress the
        // contradiction up as the compiler's own symbol.
        if (foreignRecoveredNames.contains(funcAddr.getOffset())) return null;

        Symbol entry = (func == null) ? null : func.getSymbol();
        Symbol named = null;
        Symbol stale = null;
        Symbol authoritative = null;
        for (Symbol s : symTab.getSymbols(funcAddr)) {
            if (s.getName().startsWith("_Z")) {
                // Only revise a plain label this pass wrote; imported, hand-written
                // and user-toggled mangled names are real.
                if (s.getSource() != SourceType.ANALYSIS || s.equals(entry)) {
                    authoritative = s;
                    continue;
                }
                stale = s;
                continue;
            }
            // An auto-label carries no name, only an address. Mangling one produces a
            // symbol that reads as the compiler's own and means nothing.
            if (named == null && !s.getParentNamespace().isGlobal()
                    && !isAutoLabel(s.getName())) {
                named = s;
            }
        }
        if (authoritative != null) {
            // A real name wins. An ANALYSIS spelling of the same member beside it is this
            // pass's own weaker derivation of it -- _ZNSt9exception4whatEv next to the
            // module's _ZNKSt9exception4whatEv -- and goes. A different member (a D2 alias
            // beside an imported D1) is left alone.
            String key = memberKey(authoritative.getName());
            for (Symbol s : symTab.getSymbols(funcAddr)) {
                if (s.equals(authoritative) || s.equals(entry)) continue;
                if (s.getSource() != SourceType.ANALYSIS || !s.getName().startsWith("_Z")) {
                    continue;
                }
                if (key != null && key.equals(memberKey(s.getName()))) s.delete();
            }
            return null;
        }
        if (named == null) return null;

        // A suffixed placeholder is an adjustor thunk, whose ABI name wraps the name
        // of the function it stands in for.
        String plain = named.getName();
        int subIdx = placeholderSubIndex(plain);
        if (subIdx > 0) plain = plain.substring(0, plain.lastIndexOf('_'));

        // A mangled name asserts "this is the compiler's own symbol". VF30 is not a method
        // armcc ever emitted -- it is this pass's stand-in for a slot whose name was never
        // recovered -- so _ZN11AcNpcSpShop4VF30Ev is a forgery that every downstream tool
        // (demangler, linker-map diff, symbol matcher) will take at face value. Only a
        // genuinely recovered name earns the _Z spelling; the structor codes D0/D1 are
        // recovered, because those are ABI names rather than invented ones.
        //
        // Returning null here rather than skipping early is deliberate: it routes through
        // the stale-symbol cleanup below, so a re-run deletes the fabricated names an
        // earlier run wrote instead of leaving them behind.
        boolean placeholder = isSlotPlaceholder(plain);
        if (placeholder) placeholdersLeftUnmangled++;
        // The class's own _ZTS string first, and mangle() only when there is none.
        //
        // mangle() spells the namespace out component by component, which is right only
        // when no component has an ABI abbreviation. ::std has one: armcc writes
        // _ZNSt9exceptionD0Ev, not _ZN3std9exceptionD0Ev, and the same goes for Sa, Ss,
        // Sb and the stream types. The _ZTS string is the compiler's own spelling and
        // already carries all of them -- plus templates, which mangle() cannot spell at
        // all -- so it is the better source whenever the class has one.
        //
        // And only a structor is spelled from the vtable alone. A structor has no
        // cv-qualifier and no parameters to get wrong; any other member's mangled name also
        // asserts its parameter list and const-ness, which a vtable never records
        // (ghidra_open_answers_2.md section 2). Those are spelled only where a real symbol
        // fixed the signature -- the member itself, or what it overrides. The rest keep their
        // plain Class::name label, which says everything that is actually known.
        String mangled = null;
        if (placeholder) {
            // nothing
        } else if (STRUCTOR_CODES.contains(plain)) {
            mangled = structorFromTypeName(named.getParentNamespace(), plain);
            if (mangled == null) mangled = mangle(named.getParentNamespace(), plain);
        } else {
            Signature sig = knownSignatures.get(
                    named.getParentNamespace().getName(true) + "::" + plain);
            String enc = (sig == null)
                    ? null : MangledNames.typeNameForClass(program, named.getParentNamespace());
            if (sig != null && enc != null && !enc.isEmpty()) mangled = sig.spellIn(enc);
            if (mangled == null) methodsLeftUnmangled++;
        }
        boolean virtualThunk = false;
        // A predicted adjustment is enough on its own: it comes from a non-zero vcall word,
        // which says this slot holds a thunk regardless of what size the body is or whether
        // its instructions read.
        // A contested entry is stored as null, so ask for the value rather than the key.
        boolean predicted = predictedThunks.get(funcAddr.getOffset()) != null;
        if (mangled != null
                && (predicted || subIdx > 0 || (func != null && isThunkSized(func)))) {
            ThunkAdjustment adjustment =
                    chooseAdjustment(funcAddr, thunkAdjustment(funcAddr));
            if (predicted && bodySaysNonVirtual(funcAddr)) {
                // The table read says virtual and the body says otherwise; see
                // bodySaysNonVirtual. No name beats a wrong _ZTv one.
                thunkKindConflicts++;
                if (thunkKindConflictExamples.size() < MAX_DISAGREEMENT_EXAMPLES) {
                    thunkKindConflictExamples.add(funcAddr + ": predicted virtual from its "
                            + "slot, body adjusts by a constant");
                }
                mangled = null;
            } else if (predicted) {
                mangled = asThunk(mangled, adjustment);
                virtualThunk = true;
            } else if (subIdx > 0) {
                // A suffixed placeholder is a secondary slot, and a secondary sub-table
                // holds only thunks (armcc probe Q4). The table's offset-to-top is the
                // name's number whether or not the body reads, because under -Otime the
                // body carries the forwarded-to function's constants as well.
                if (adjustment != null) {
                    mangled = asThunk(mangled, adjustment);
                    virtualThunk = adjustment.isVirtual();
                } else {
                    mangled = null;
                }
            } else if (adjustment != null && adjustment.isVirtual()) {
                // A primary sub-table can hold a thunk too, but only the virtual kind:
                // a class reaches an override in a virtual base through a vcall offset
                // from its own primary vptr. The non-virtual kind is deliberately not
                // honoured here -- this-adjustment in a primary table is zero by
                // definition, so a bare "add r0,#4" in a short primary slot is a real
                // function doing arithmetic, not a thunk.
                mangled = asThunk(mangled, adjustment);
                virtualThunk = true;
            }
        }
        return new MangledPlan(mangled, stale, virtualThunk);
    }

    /**
     * A member's mangled name with its cv-qualifiers and parameter list taken out, so two
     * spellings of the same member compare equal: {@code _ZNKSt9exception4whatEv} and
     * {@code _ZNSt9exception4whatEv} both give {@code St9exception4what}.
     */
    private static String memberKey(String mangled) {
        if (mangled == null || !mangled.startsWith("_ZN")) return null;
        int i = 3;
        while (i < mangled.length() && "rVK".indexOf(mangled.charAt(i)) >= 0) i++;
        int end = mangled.lastIndexOf('E');
        if (end <= i) return null;
        return mangled.substring(i, end);
    }

    /** The Itanium structor codes, the only names spellable without knowing a signature. */
    private static final Set<String> STRUCTOR_CODES =
            Set.of("D0", "D1", "D2", "C1", "C2", "C3");

    /**
     * A structor's mangled name built from the compiler's own {@code _ZTS} spelling of the
     * class, for the classes {@link #mangle} has to give up on.
     *
     * <p>{@code mangle} spells the namespace out component by component and refuses
     * anything that is not a plain identifier, which rules out every template:
     * {@code sead::FixedSafeString<20>} has no identifier spelling. But the class's own
     * {@code _ZTS} string already holds armcc's encoding of it, and a structor is the one
     * member whose name can be built from that alone -- there is no signature to spell,
     * and no later part of the name refers back to the class's components, so no
     * substitution numbering has to be replayed. That left 598 template destructors
     * carrying bare {@code D1}/{@code D0} placeholders.
     *
     * <p>The {@code E} bookkeeping is where this is easy to get wrong. {@code _ZTS} for a
     * nested class is {@code N <components> E}; the destructor is
     * {@code _ZN <components> D1 E v}, so the {@code E} moves from before the structor
     * code to after it -- it closes the nesting, and {@code v} is the void parameter list.
     * A class with no nesting has no {@code N} in its {@code _ZTS} at all
     * ({@code 7UtlBaseI9DemoActorE}, where that {@code E} closes the template arguments),
     * and one has to be added.
     */
    private String structorFromTypeName(Namespace ns, String plain) {
        if (ns == null) return null;
        String member;
        if (STRUCTOR_CODES.contains(plain)) {
            member = plain;
        } else if (isPlainIdentifier(plain)) {
            member = plain.length() + plain;
        } else {
            return null;
        }
        String enc = MangledNames.typeNameForClass(program, ns);
        if (enc == null || enc.isEmpty()) return null;
        String nested;
        if (enc.charAt(0) == 'N') {
            if (enc.charAt(enc.length() - 1) != 'E') return null;
            nested = enc.substring(0, enc.length() - 1);
        } else {
            nested = "N" + enc;
        }
        return "_Z" + nested + member + "Ev";
    }

    /**
     * Itanium mangling for a nested member function taking no arguments: A::B::VF02
     * becomes _ZN1A1B4VF02Ev, D1/D0 become _ZN1A1BD1Ev / _ZN1A1BD0Ev. The structor
     * codes C1/C2/C3 are spelled the same way, for MakeConstructor. Null for
     * anything unspellable that way, such as templates and operators.
     */
    public static String mangle(Namespace ns, String name) {
        List<String> parts = new ArrayList<>();
        for (Namespace n = ns; n != null && !n.isGlobal(); n = n.getParentNamespace()) {
            if (!isPlainIdentifier(n.getName())) return null;
            // Guard against Ghidra's auto-generated switch namespaces
            if (n.getName().startsWith("switchD_")) return null;
            parts.addFirst(n.getName());
        }
        if (parts.isEmpty()) return null;

        StringBuilder sb = new StringBuilder("_ZN");
        for (String part : parts) sb.append(part.length()).append(part);

        if (name.equals("D0") || name.equals("D1") || name.equals("D2")
                || name.equals("C1") || name.equals("C2") || name.equals("C3")) {
            sb.append(name);
        } else if (isPlainIdentifier(name)) {
            sb.append(name.length()).append(name);
        } else {
            return null;
        }
        return sb.append("Ev").toString();
    }

    /**
     * The Itanium {@code <name>} production for a class: what follows _ZTV, _ZTI or _ZTS.
     * A::B becomes N1A1BE, a top-level Foo becomes 3Foo. Null for the same unspellable
     * cases mangle() gives up on. MangledNames prefers the compiler's own _ZTS spelling
     * and falls back to this.
     */
    public static String mangleTypeName(Namespace ns) {
        List<String> parts = new ArrayList<>();
        for (Namespace n = ns; n != null && !n.isGlobal(); n = n.getParentNamespace()) {
            if (!isPlainIdentifier(n.getName())) return null;
            if (n.getName().startsWith("switchD_")) return null;
            parts.addFirst(n.getName());
        }
        if (parts.isEmpty()) return null;

        StringBuilder sb = new StringBuilder();
        for (String part : parts) sb.append(part.length()).append(part);
        // A single component stands alone; anything nested is wrapped in N...E
        return (parts.size() == 1) ? sb.toString() : "N" + sb + "E";
    }

    /** The sub-vtable index of a suffixed placeholder such as D1_1 or F05_2, else -1. */
    private static int placeholderSubIndex(String name) {
        if (!isPlaceholder(name)) return -1;
        int us = name.lastIndexOf('_');
        if (us < 0) return -1;
        try {
            return Integer.parseInt(name.substring(us + 1));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /**
     * What an adjustor thunk does to {@code this} before it hands off.
     *
     * @param nonVirtual  the immediate added to (or subtracted from) this
     * @param vcallOffset the displacement below the vptr the adjustment is loaded from,
     *                    or null when the thunk adjusts by a constant alone
     */
    private record ThunkAdjustment(int nonVirtual, Integer vcallOffset) {
        boolean isVirtual() {
            return vcallOffset != null;
        }
    }

    /**
     * The this-adjustment an adjustor thunk applies, read from its own first few
     * instructions. Null means nothing recognisable was found, which also answers
     * whether this is a thunk at all â€” a slot can hold a real override.
     *
     * <p>Two shapes are accepted. The non-virtual one is a bare {@code add}/{@code sub}
     * on r0. The virtual one, which a class reaching an override through a virtual base
     * needs, loads the vptr from this and then loads its adjustment from a <em>negative</em>
     * displacement off that vptr: the vcall offsets sit below the address point, where
     * nothing else a thunk could be doing reads from. Both halves have to be present for
     * the negative load to mean a vcall offset, which is what keeps an ordinary member
     * read out.
     *
     * <p>Anything that does not read exactly this way returns null and no thunk name is
     * emitted. A number in an ABI name is either right or actively misleading, so the
     * bar is a shape armcc was seen to emit rather than anything that could be one.
     */
    private ThunkAdjustment thunkAdjustment(Address funcAddr) {
        Function func = program.getListing().getFunctionAt(funcAddr);
        if (func == null) return null;
        // A linker veneer is a hop inserted to reach a far target, not a compiler-generated
        // adjustor thunk -- vtables.md S2 is explicit that the two are different things.
        // Reading an immediate out of one would invent an adjustment the ABI never spelled.
        if (isVeneer(funcAddr)) return null;
        Register thisReg = program.getLanguage().getRegister("r0");
        if (thisReg == null) return null;

        Integer nonVirtual = null;
        Integer vcall = null;
        Register vptrReg = null;
        // Two *vcall* readings that disagree are not a thunk we understand. Differing
        // this-adjustment constants are ordinary under -Otime and no longer count.
        boolean ambiguous = false;
        Set<Integer> bodyConstants = new HashSet<>();

        try {
            InstructionIterator iter =
                    program.getListing().getInstructions(func.getBody(), true);
            // Eight rather than the four the immediate form needed: the virtual form
            // spends two loads reaching the vcall offset before it touches r0 at all.
            for (int seen = 0; iter.hasNext() && seen < 8; seen++) {
                Instruction inst = iter.next();
                String mnemonic = inst.getMnemonicString().toLowerCase();

                boolean subtract = mnemonic.startsWith("sub");
                if (subtract || mnemonic.startsWith("add")) {
                    // The adjustment reads off r0 but need not land back in it: armcc
                    // emits "SUB r4,r0,#0x28" for a D0 thunk, fusing the adjustment into
                    // the register it keeps `this` in. So r0 has to be the *source*.
                    //
                    // Testing the destination instead lets stack arithmetic in --
                    // "ADD r0,sp,#0x1580" computes a local's address and says nothing
                    // about this -- which is where the cross-check's nonsense constants
                    // (16384, 5504) came from. The two-operand form has no second
                    // register, and there r0 as destination is r0 as source.
                    Register src = inst.getRegister(1);
                    boolean readsThis = thisReg.equals(src)
                            || (src == null && thisReg.equals(inst.getRegister(0)));
                    if (!readsThis) continue;
                    for (int op = 1; op < inst.getNumOperands(); op++) {
                        Scalar delta = inst.getScalar(op);
                        if (delta == null) continue;
                        long value = delta.getUnsignedValue();
                        int adjust = (int) (subtract ? -value : value);
                        // Every constant is collected, because under -Otime the thunk
                        // inlines the destructor and the body then also holds member
                        // offsets ("ADD r0,r4,#0x44 ; BL Member::D1 ; SUB r0,r0,#0x44")
                        // and virtual-base displacements. Several differing constants is
                        // the normal case, not an ambiguity -- treating it as one is why
                        // ACNL's #76 and #228 read as contradictions when they are just
                        // member offsets inside the complete object.
                        bodyConstants.add(adjust);
                        if (nonVirtual == null) nonVirtual = adjust;
                        break;
                    }
                    // The virtual form's "add r0,r0,r3" carries no scalar, so it falls
                    // through here without being mistaken for a constant adjustment.
                    continue;
                }

                // Only a plain, unconditional word load counts. A byte or halfword load,
                // a predicated one, or a register-offset address is not a shape armcc
                // emits for this, and reading one would be a guess.
                if (!mnemonic.equals("ldr")) continue;
                Register dest = inst.getRegister(0);
                Register base = null;
                long disp = 0;
                for (int op = 1; op < inst.getNumOperands(); op++) {
                    Object[] objs = inst.getOpObjects(op);
                    if (objs.length == 0 || objs.length > 2) continue;
                    if (!(objs[0] instanceof Register r)) continue;
                    if (objs.length == 2) {
                        if (!(objs[1] instanceof Scalar s)) continue;
                        disp = s.getSignedValue();
                    }
                    base = r;
                    break;
                }
                if (dest == null || base == null) continue;

                if (thisReg.equals(base) && disp == 0) {
                    // The vptr: the only thing at this+0 in an armcc object.
                    if (vptrReg != null && !vptrReg.equals(dest)) ambiguous = true;
                    vptrReg = dest;
                } else if (vptrReg != null && vptrReg.equals(base) && disp < 0) {
                    if (vcall == null) vcall = (int) disp;
                    else if (vcall != disp) ambiguous = true;
                }
            }
        } catch (Exception e) {
            return null;
        }

        if (ambiguous) return null;
        // A positive immediate does NOT mean this is not a thunk. That rule was added from
        // nn::nex::DataStoreLogicServerClient, whose secondary slots all read
        // "add r0,r0,#8", and armcc probe q1q4_thunks.py shows the reading was wrong:
        // armcc inlines the forwarded-to body into the thunk and constant-folds the two
        // adjustments together, so Client::Do with base at +16 and member at +24 comes out
        // as "_ZThn16_N6Client2DoEff: ADD r0,r0,#8 ; B _ZN4Impl4callEff" -- one thunk,
        // named for the base, whose body shows the sum. A secondary sub-table holds
        // thunks and nothing else; the plain function lives in the primary part.
        if (vcall != null) {
            // A virtual thunk that adjusts by the loaded amount alone still has a
            // non-virtual part in its name; the ABI spells that part zero.
            return new ThunkAdjustment(nonVirtual == null ? 0 : nonVirtual, vcall);
        }
        bodyConstantCache.put(funcAddr.getOffset(), bodyConstants);
        return (nonVirtual == null) ? null : new ThunkAdjustment(nonVirtual, null);
    }

    /** Every this-relative constant a thunk body was seen to apply, by function address. */
    private final Map<Long, Set<Integer>> bodyConstantCache = new HashMap<>();

    /** A linker veneer, which belongs to no class. Same guard as NonVirtualAssigner. */
    private boolean isVeneer(Address addr) {
        for (Symbol sym : symTab.getSymbols(addr)) {
            if (sym.getName().startsWith("$Ven$")) return true;
        }
        return false;
    }

    /**
     * Wrap a mangled name as the thunk forwarding to it: _ZN5AcFtrD1Ev with a -104
     * adjustment becomes _ZThn104_N5AcFtrD1Ev, and with a vcall offset of -12 on top of
     * it _ZTv0_n12_N5AcFtrD1Ev.
     *
     * <p>The this-adjustment comes first, then the vcall offset --
     * {@code <call-offset> ::= v <offset number> _ <virtual offset number> _}. This used to
     * emit them the other way round, so every virtual thunk came out as _ZTvn12_0_ instead
     * of armcc's own _ZTv0_n12_.
     */
    private String asThunk(String mangled, ThunkAdjustment adjustment) {
        String nonVirtual = itaniumOffset(adjustment.nonVirtual());
        if (!adjustment.isVirtual()) {
            return "_ZTh" + nonVirtual + "_" + mangled.substring(2);
        }
        return "_ZTv" + nonVirtual + "_" + itaniumOffset(adjustment.vcallOffset()) + "_"
                + mangled.substring(2);
    }

    /** Itanium's spelling of a signed offset: a leading n rather than a minus sign. */
    private static String itaniumOffset(int value) {
        return (value < 0) ? "n" + (-(long) value) : Long.toString(value);
    }

    private static boolean isPlainIdentifier(String s) {
        if (s.isEmpty() || Character.isDigit(s.charAt(0))) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c > 127) return false;
            if (!Character.isLetterOrDigit(c) && c != '_') return false;
        }
        return true;
    }

    // ---------------------------------------------------------------
    //  Vtable ingestion (whole groups, from VtableScan)
    // ---------------------------------------------------------------

    /**
     * Take each class's own vtable from {@link VtableScan} and apply it.
     *
     * <p>This replaces the old slot-at-a-time walk, which appended every table carrying a
     * class's typeinfo to that class in address order and called the first one primary.
     * ARMCC emits a construction vtable under the base's typeinfo for each class deriving
     * from it, so a class with five such children looked like it had eleven sub-vtables.
     * Every one of those phantoms produced a round of VF&lt;nn&gt;_&lt;n&gt; placeholders,
     * a bogus _ZThn thunk name and a junk _vfuncs_&lt;n&gt; struct, and it split the real
     * destructor pair across two of them.
     *
     * @param candidateSlots the RTTI slots RTTIUtil found, used only as a cross-check
     */
    private void ingestGroups(Map<Long, Long> candidateSlots, TaskMonitor monitor)
            throws Exception {
        vtableScan = new VtableScan(program, typeinfoToClassName, typeinfoSizes(),
                baseInfoMap, script::println, monitor);
        // A table built for a class from another module carries that class's typeinfo as
        // an import; the same resolution the inheritance tree uses names it.
        // Strictly: a vtable slot importing a *function* must not read as one, so only a
        // target that is labelled typeinfo, or whose name pointer is a valid _ZTS string.
        vtableScan.setImportedTypeinfoResolver(at -> {
            ExternalTypeinfoResult r = resolveExternalTypeinfo(program, at);
            if (r == null) return null;
            Address t = r.program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(r.typeinfoAddr);
            for (Symbol s : r.program.getSymbolTable().getSymbols(t)) {
                if (s.getName().equals("typeinfo") || s.getName().startsWith("_ZTI")) {
                    return r.className;
                }
            }
            return (Demangler.classNameOfTypeinfo(r.program, t) != null) ? r.className : null;
        });
        vtableScan.scan();
        vtableScan.printSummary();

        int ingested = 0;
        for (VtableScan.VtableGroup group : vtableScan.groups()) {
            if (!group.isReal()) continue;
            String className = group.className();
            if (allVtableSlots.containsKey(className)) {
                script.printf("    WARNING: %s has more than one group marked as its own; " +
                        "keeping the one at %s\n", className,
                        allVtableSubTables.get(className).get(0).head());
                continue;
            }

            List<List<Long>> slotLists = new ArrayList<>();
            List<Address> points = new ArrayList<>();
            List<Address> heads = new ArrayList<>();
            for (VtableScan.SubTable sub : group.subs()) {
                applySubTableData(sub);
                slotLists.add(sub.slots());
                points.add(sub.addressPoint());
                heads.add(sub.head());
            }

            allVtableSlots.put(className, slotLists);
            allVtableAddressPoints.put(className, points);
            allVtableHeads.put(className, heads);
            allVtableSubTables.put(className, group.subs());
            // The primary is the group's first sub-table by structure, not the
            // lowest-addressed table that happened to carry this typeinfo.
            vtableSlots.put(className, slotLists.get(0));
            vtableAddressPoints.put(className, points.get(0));
            vtableHeads.put(className, heads.get(0));
            ingested++;
        }

        int subTables = 0;
        for (List<List<Long>> lists : allVtableSlots.values()) subTables += lists.size();
        script.printf("    Vtables ingested:       %d classes, %d sub-tables " +
                "(from %d candidate RTTI slots)\n",
                ingested, subTables, candidateSlots.size());
    }

    /**
     * Type the words of one sub-table: the virtual-base offsets, the offset-to-top, the
     * typeinfo pointer and the function slots.
     *
     * <p>Clearing first matters on a re-run. A corrected head sits earlier than the one a
     * previous run used -- a virtual-base class's head moves back one word per virtual
     * base -- so the old data would still be applied over the new head and the new
     * application would silently fail.
     */
    private void applySubTableData(VtableScan.SubTable sub) {
        Listing listing = program.getListing();
        Address last = sub.end().subtract(1);
        try {
            listing.clearCodeUnits(sub.head(), last, true);
        } catch (Exception e) {
            // Leave whatever is there; the per-word application below still tries.
        }
        for (int i = 0; i < sub.vbaseCount(); i++) {
            applyData(sub.head().add((long) PTR_SIZE * i), IntegerDataType.dataType);
        }
        applyData(sub.offsetToTopAddr(), IntegerDataType.dataType);
        applyData(sub.rttiSlot(), PointerDataType.dataType);
        for (int i = 0; i < sub.slots().size(); i++) {
            applyData(sub.addressPoint().add((long) PTR_SIZE * i), PointerDataType.dataType);
        }
    }

    /** Apply one data type, preserving any external reference the slot already carries. */
    private void applyData(Address addr, DataType type) {
        try {
            Reference extRef = null;
            for (Reference ref : program.getReferenceManager().getReferencesFrom(addr)) {
                if (ref.isExternalReference()) {
                    extRef = ref;
                    break;
                }
            }
            program.getListing().clearCodeUnits(addr, addr, true);
            program.getListing().createData(addr, type);
            if (extRef != null) program.getReferenceManager().addReference(extRef);
        } catch (Exception e) {
            // Already applied, or the address is not in memory.
        }
    }

    /**
     * Typeinfo address -> applied struct size, which is what tells the scan where a
     * typeinfo body ends. The base-class pointers inside one are not vtable RTTI slots.
     */
    private Map<Long, Integer> typeinfoSizes() {
        Map<Long, Integer> sizes = new HashMap<>();
        for (long addr : typeinfoAddresses) {
            try {
                Data data = program.getListing().getDataAt(toAddress(addr));
                sizes.put(addr, (data != null) ? data.getLength() : 8);
            } catch (Exception e) {
                sizes.put(addr, 8);
            }
        }
        return sizes;
    }

    // ---------------------------------------------------------------
    //  Slot-0 cross-hierarchy link
    // ---------------------------------------------------------------

    /** Individually listed cases, matching the unreached-class reporting. */
    private static final int MAX_SLOT0_REPORTS = 20;

    /** Classes named per shared value before the rest are counted instead. */
    private static final int MAX_SLOT0_CLASSES_PER_VALUE = 4;

    /**
     * Look for hierarchies the typeinfo graph keeps apart but slot 0 ties together.
     *
     * <p>What slot 0 fixes is the *index*: a derived class may overwrite an inherited
     * slot or append new ones, but cannot move one (vtables.md S1, "Slot order"). The
     * value is not fixed. vtables.md's own example has Leaf::gti at the index Root::gti
     * occupies, and that is ordinary C++ -- an override, not a grouping fault. So the
     * inference runs one way only:
     *
     * <ul>
     * <li><b>same slot-0 value =&gt; very likely one hierarchy.</b> One class inherited
     *     slot 0 from the other and did not override it. When the graph puts them in
     *     different components, the joining edge is one the typeinfo graph could not
     *     see -- the normal shape when the root lives in another CRO module. That is
     *     the "cheap way to find the hierarchy's extent with no symbols".</li>
     * <li><b>different slot-0 values =&gt; nothing at all.</b> Any derived class that
     *     overrides slot 0 produces one, so the difference carries no information about
     *     the grouping. An earlier revision reported these as suspected grouping faults:
     *     measured on the real image it flagged 134 of 138 hierarchies, i.e. 97% false
     *     alarm and no signal. Do not re-add it.</li>
     * </ul>
     *
     * <p>Report-only on purpose: nothing here renames a slot or revisits which group a
     * class was given. A shared value is a statement about VtableScan's classification,
     * and repairing it from this side would hide the very thing the check surfaces.
     */
    private void linkHierarchiesBySlotZero() throws Exception {
        // Connected components over the undirected inheritance graph. The walk crosses
        // classes that have no vtable of their own -- an abstract or external base is
        // still what joins its children, and dropping it would split one hierarchy into
        // several and then report the halves back as candidate merges.
        Map<String, Integer> componentOf = new HashMap<>();
        List<List<String>> components = new ArrayList<>();
        for (String seed : typeinfoToClassName.values()) {
            if (componentOf.containsKey(seed)) continue;
            int id = components.size();
            List<String> members = new ArrayList<>();
            ArrayDeque<String> queue = new ArrayDeque<>();
            componentOf.put(seed, id);
            queue.add(seed);
            while (!queue.isEmpty()) {
                String current = queue.poll();
                members.add(current);
                for (String neighbour : neighbours(current)) {
                    if (componentOf.putIfAbsent(neighbour, id) == null) {
                        queue.add(neighbour);
                    }
                }
            }
            components.add(members);
        }

        // component -> slot-0 value -> the classes holding it
        Map<Integer, Map<Long, List<String>>> byComponent = new LinkedHashMap<>();
        for (String className : vtableSlots.keySet()) {
            Long slotZero = comparableSlotZero(className);
            if (slotZero == null) continue;
            Integer id = componentOf.get(className);
            if (id == null) continue;
            byComponent.computeIfAbsent(id, k -> new LinkedHashMap<>())
                    .computeIfAbsent(slotZero, k -> new ArrayList<>())
                    .add(className);
        }

        // value -> the components it was seen in. A value confined to one component is
        // just an inherited slot inside a hierarchy the graph already found; only one
        // seen in two or more says anything new.
        int comparableClasses = 0;
        Map<Long, List<Integer>> valueToComponents = new LinkedHashMap<>();
        // value -> the classes holding it, so a shared value can name them
        Map<Long, List<String>> valueToClasses = new LinkedHashMap<>();

        for (Map.Entry<Integer, Map<Long, List<String>>> entry : byComponent.entrySet()) {
            for (Map.Entry<Long, List<String>> holder : entry.getValue().entrySet()) {
                valueToComponents.computeIfAbsent(holder.getKey(), k -> new ArrayList<>())
                        .add(entry.getKey());
                valueToClasses.computeIfAbsent(holder.getKey(), k -> new ArrayList<>())
                        .addAll(holder.getValue());
                comparableClasses += holder.getValue().size();
            }
        }

        int merges = 0;
        int mergesListed = 0;
        for (Map.Entry<Long, List<Integer>> entry : valueToComponents.entrySet()) {
            List<Integer> ids = entry.getValue();
            if (ids.size() < 2) continue;
            merges++;
            if (mergesListed++ >= MAX_SLOT0_REPORTS) continue;

            List<String> names = new ArrayList<>();
            for (int id : ids) {
                List<String> members = components.get(id);
                names.add(hierarchyName(members) + " (" + members.size() + ")");
            }
            script.printf("    SLOT0 CROSS-HIERARCHY: 0x%08x heads %d hierarchies the " +
                    "typeinfo graph keeps apart: %s\n",
                    entry.getKey(), ids.size(), String.join(", ", names));

            List<String> classes = valueToClasses.get(entry.getKey());
            String shown = String.join(", ",
                    classes.subList(0, Math.min(classes.size(),
                            MAX_SLOT0_CLASSES_PER_VALUE)));
            if (classes.size() > MAX_SLOT0_CLASSES_PER_VALUE) {
                shown += " and " + (classes.size() - MAX_SLOT0_CLASSES_PER_VALUE)
                        + " more";
            }
            script.printf("        held by %s\n", shown);
        }
        if (merges > MAX_SLOT0_REPORTS) {
            script.println("... and " + (merges - MAX_SLOT0_REPORTS) +
                    " more slot-0 values shared across hierarchies.");
        }

        script.printf("    Slot-0 links:           %d classes with a comparable slot 0 " +
                "across %d hierarchies; %d values shared across hierarchies\n",
                comparableClasses, byComponent.size(), merges);
    }

    /** Both directions of the inheritance edge, so the component walk is undirected. */
    private List<String> neighbours(String className) {
        List<String> all = new ArrayList<>();
        all.addAll(parentMap.getOrDefault(className, List.of()));
        all.addAll(childrenMap.getOrDefault(className, List.of()));
        return all;
    }

    /** A component's root if it has exactly one, else its first member by name. */
    private String hierarchyName(List<String> members) {
        List<String> roots = new ArrayList<>();
        for (String member : members) {
            if (parentMap.getOrDefault(member, List.of()).isEmpty()) roots.add(member);
        }
        List<String> pool = roots.isEmpty() ? members : roots;
        String best = pool.get(0);
        for (String candidate : pool) {
            if (candidate.compareTo(best) < 0) best = candidate;
        }
        return (roots.size() > 1) ? best + " et al" : best;
    }

    /**
     * The slot-0 value of a class's primary sub-table, or null when it cannot carry the
     * comparison. Three things are excluded, each because a match on it would be a match
     * on something other than a shared inherited slot:
     *
     * <ul>
     * <li>an empty primary sub-table -- there is no word to read;</li>
     * <li>a zero slot, or one whose word is really an import into another module: the
     *     value in memory is a placeholder the loader fills, so two classes matching on
     *     it are matching on the absence of an address;</li>
     * <li>__cxa_pure_virtual, which every abstract class in the image shares. Unrelated
     *     abstract roots agree on it for a reason that has nothing to do with descent,
     *     so it would link every one of them to every other.</li>
     * </ul>
     */
    private Long comparableSlotZero(String className) throws MemoryAccessException {
        List<Long> slots = vtableSlots.get(className);
        if (slots == null || slots.isEmpty()) return null;
        long value = slots.get(0);
        if (value == 0) return null;

        Address point = vtableAddressPoints.get(className);
        if (point == null) return null;
        for (Reference ref : program.getReferenceManager().getReferencesFrom(point)) {
            if (ref instanceof ExternalReference) return null;
        }
        if (isPureVirtualRef(point)) return null;

        // The thumb bit belongs to the branch, not to the function's identity.
        return value & ~1L;
    }

    private Address toAddress(long offset) {
        return program.getMinAddress().getAddressSpace().getAddress(offset);
    }

    /**
     * Detect __cxa_pure_virtual by finding a function pointer that appears
     * in vtable slots of two classes that share no inheritance relationship.
     */
    private void detectPureVirtual() throws Exception {
        // Pass 1: group non-zero slot values by class
        Map<Long, Set<String>> valuesToClasses = new HashMap<>();
        for (Map.Entry<String, List<List<Long>>> entry : allVtableSlots.entrySet()) {
            String className = entry.getKey();
            for (List<Long> subVtable : entry.getValue()) {
                for (long val : subVtable) {
                    if (val == 0) continue;
                    valuesToClasses.computeIfAbsent(val, k -> new HashSet<>())
                            .add(className);
                }
            }
        }

        List<Long> candidates = new ArrayList<>();
        for (Map.Entry<Long, Set<String>> entry : valuesToClasses.entrySet()) {
            if (entry.getValue().size() < 2) continue;
            if ((entry.getKey() & 1L) == 0) continue;
            if (hasUnrelatedPair(entry.getValue())) {
                candidates.add(entry.getKey());
            }
        }

        if (!candidates.isEmpty()) {
            candidates.sort(Comparator.comparingInt(k -> valuesToClasses.get(k).size()).reversed());
            pureVirtualAddr = candidates.getFirst() & ~1L;
            script.println("    Detected __cxa_pure_virtual at 0x" +
                    Long.toHexString(pureVirtualAddr) +
                    " (thumb function which appears in unrelated vtables)");
            AddressSpace addrSpace = program.getMinAddress().getAddressSpace();
            Address pureVirtual = addrSpace.getAddress(pureVirtualAddr);
            // Disassemble before creating, or the body is derived from undisassembled
            // bytes and comes out one byte long. Only thumb pointers reach the
            // candidate list, hence thumb = true.
            if (program.getListing().getInstructionAt(pureVirtual) == null) {
                new ArmDisassembleCommand(pureVirtual, null, true).applyTo(program);
            }
            CreateFunctionCmd cmd = new CreateFunctionCmd("__cxa_pure_virtual",
                    pureVirtual, null, SourceType.USER_DEFINED);
            cmd.applyTo(program);
            // CreateFunctionCmd does nothing where a function already exists -- and one does
            // once the CROs are linked, since 24 of them import this address and an import
            // target is made a function. Name the existing one instead.
            Function pv = program.getFunctionManager().getFunctionAt(pureVirtual);
            if (pv != null && !pv.getName().equals("__cxa_pure_virtual")) {
                try {
                    pv.setName("__cxa_pure_virtual", SourceType.USER_DEFINED);
                } catch (Exception e) {
                    script.println("    WARNING: could not name __cxa_pure_virtual at "
                            + pureVirtual + ": " + e.getMessage());
                }
            }
            if (candidates.size() > 1) {
                script.println("    WARNING: " + candidates.size() +
                        " candidates found for __cxa_pure_virtual:");
                for (long addr : candidates) {
                    script.println("  0x" + Long.toHexString(addr) +
                            " (" + valuesToClasses.get(addr).size() + " classes)");
                }
            }
            return;
        }

        // Pass 2: group zero-valued slots (external refs) by target
        Map<ExternalLocation, Set<String>> extKeyToClasses = new HashMap<>();
        ReferenceManager refMgr = program.getReferenceManager();
        for (Map.Entry<String, List<List<Long>>> entry : allVtableSlots.entrySet()) {
            String className = entry.getKey();
            List<List<Long>> subVtables = entry.getValue();
            List<Address> addrPoints = allVtableAddressPoints.get(className);
            if (addrPoints == null) continue;

            for (int s = 0; s < subVtables.size(); s++) {
                if (s >= addrPoints.size() || addrPoints.get(s) == null) continue;
                Address base = addrPoints.get(s);
                List<Long> slots = subVtables.get(s);
                for (int i = 0; i < slots.size(); i++) {
                    if (slots.get(i) != 0) continue;
                    Address slotAddr = base.add(4L * i);
                    for (Reference ref : refMgr.getReferencesFrom(slotAddr)) {
                        if (ref instanceof ExternalReference extRef) {
                            ExternalLocation loc = extRef.getExternalLocation();
                            extKeyToClasses.computeIfAbsent(loc, k -> new HashSet<>())
                                    .add(className);
                        }
                    }
                }
            }
        }

        Set<ExternalLocation> extCandidates = new HashSet<>();
        ProgramManager pman = Programs.manager(script);
        for (Map.Entry<ExternalLocation, Set<String>> entry : extKeyToClasses.entrySet()) {
            Address extAddr = entry.getKey().getAddress();
            String libName = entry.getKey().getLibraryName();
            String libPath = program.getExternalManager().getExternalLibraryPath(libName);
            Program extProg;
            try {
                extProg = Programs.open(script.parseDomainFile(libPath), this, pman,
                        script.getMonitor());
            } catch (Exception e) {
                continue;
            }
            if (extProg == null) continue;
            // setName throws on a duplicate or an invalid name, and the release used to sit
            // after it -- so one bad name pinned the module open for the session.
            try {
                Symbol[] syms = extProg.getSymbolTable().getSymbols(extAddr);
                boolean located = false;
                for (var sym : syms) {
                    if (sym.getName().contains("cxa_pure_virtual")) {
                        extCandidates.add(entry.getKey());
                        entry.getKey().getSymbol()
                                .setName("__cxa_pure_virtual", SourceType.USER_DEFINED);
                        located = true;
                    }
                }
                if (!located && (extAddr.getOffset() & 1L) == 1) {
                    syms = extProg.getSymbolTable().getSymbols(extAddr.subtract(1));
                    for (var sym : syms) {
                        if (sym.getName().contains("cxa_pure_virtual")) {
                            extCandidates.add(entry.getKey());
                            entry.getKey().getSymbol()
                                    .setName("__cxa_pure_virtual", SourceType.USER_DEFINED);
                        }
                    }
                }
            } finally {
                extProg.release(this);
            }
        }

        if (extCandidates.isEmpty()) {
            return;
        }

        ExternalLocation loc = extCandidates.stream().findFirst().get();
        externalPureVirtual = true;
        pureVirtualAddr = loc.getAddress() != null ? loc.getAddress().getOffset() : 0;
        script.println("    Detected external __cxa_pure_virtual: " + loc +
                " in " + loc.getLibraryName());

        if (extCandidates.size() > 1) {
            script.println("    WARNING: " + extCandidates.size() +
                    " external candidates found for __cxa_pure_virtual:");
            extCandidates.stream().sorted(Comparator.comparingInt(
                    key -> extKeyToClasses.get(key).size()))
                    .forEach(key -> script.println("  " + key +
                    " (" + extKeyToClasses.get(key).size() + " classes)"));
        }
    }

    private boolean hasUnrelatedPair(Set<String> classes) {
        List<String> list = new ArrayList<>(classes);
        for (int i = 0; i < list.size() - 1; i++) {
            for (int j = i + 1; j < list.size(); j++) {
                if (findCommonAncestor(list.get(i), list.get(j)) == null) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Check if a value at an address is a function pointer:
     * points into .text or has an external reference to a function.
     */
    private boolean isFunctionPointer(Address addr, long value) {
        // Check external reference first
        ReferenceManager refMgr = program.getReferenceManager();
        for (Reference ref : refMgr.getReferencesFrom(addr)) {
            if (ref instanceof ExternalReference) {
                return true;
            }
        }

        // Check if value points to executable memory (with thumb bit cleared)
        return isExecutable(value) || isExecutable(value & ~1L);
    }

    private boolean isExecutable(long value) {
        try {
            AddressSpace addressSpace = program.getMinAddress().getAddressSpace();
            Address targetAddr = addressSpace.getAddress(value);
            MemoryBlock block = mem.getBlock(targetAddr);
            return (block != null && block.isExecute());
        } catch (Exception e) {
            return false;
        }
    }

    private MemoryBlock findRodataBlock(Program program) {
        Memory m = program.getMemory();
        for (MemoryBlock block : m.getBlocks()) {
            String name = block.getName();
            if (name.equals(".rodata") || name.equals("rodata")) {
                return block;
            }
        }
        for (MemoryBlock block : m.getBlocks()) {
            if (block.isRead() && !block.isWrite() && !block.isExecute()) {
                return block;
            }
        }
        return null;
    }

    // ---------------------------------------------------------------
    //  Namespace collection
    // ---------------------------------------------------------------

    private void collectNamespaces() {
        SymbolIterator iter = symTab.getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol sym = iter.next();
            if (!sym.getName().equals("typeinfo")) continue;
            // Imported typeinfos sit under the exporting module's Library namespace, which
            // cannot become a class ("Could not convert |static| to class").
            if (sym.isExternal()) continue;
            Namespace ns = sym.getParentNamespace();
            if (ns == null || ns.isGlobal()) continue;
            String className = ns.getName(true);
            if (!(ns instanceof GhidraClass)) {
                try {
                    ns = NamespaceUtils.convertNamespaceToClass(ns);
                } catch (Exception e) {
                    script.println("WARNING: Could not convert " + className + " to class");
                }
            }
            classNamespaces.put(className, ns);
            classTypeinfoAddrs.putIfAbsent(className, sym.getAddress());
        }
    }

    // ---------------------------------------------------------------
    //  Class processing (rename logic)
    // ---------------------------------------------------------------

    private int constructionOnlyNamed = 0;
    private int constructionOnlyClasses = 0;

    /**
     * Name the slots of a class whose only tables are other classes' construction vtables.
     *
     * <p>An abstract base whose constructors are all inlined loses its {@code _ZTV} to
     * unused-section elimination, so the walk above never visits it -- and with it goes
     * every slot that appears <em>only</em> in its table. {@code AcObjectBase} is one:
     * eight {@code _ZT_C*_} tables carry its typeinfo, all of them put its D1 at
     * {@code 0x1f50a8} (a four-byte {@code B Actor::D1}, the {@code -Otime} collapse of a
     * trivial destructor) and its D0 at {@code 0x1f5098}, and neither address occurs in any
     * real vtable in the image. So the pair went unnamed, and {@code 0x1f50a8} kept the
     * name Ghidra gives a thunk -- its target's, {@code Actor::D1}.
     *
     * <p>A construction table's leading bytes are the class's own table (the doc measures
     * 168 identical bytes), so reading the layout off one is reading the class's own. Only
     * slots the ownership pass gives to <em>this</em> class are named, which is what keeps
     * the inherited ones -- {@code Actor::VF02} and friends, sitting in the same table --
     * with the base that declares them.
     */
    private void nameConstructionOnlyClasses() throws Exception {
        if (vtableScan == null) return;

        // Every primary construction sub-table the class has, not just the biggest one.
        // A class can appear in two derived classes' construction tables with different
        // slot targets: nn::fs::IOutputStream's table under FileStream holds _ZTv0_n12_
        // thunks in the destructor slots, because there it is reached through a virtual
        // base, while the one under FileOutputStream holds the plain functions. Taking the
        // table with the most slots took the thunks and left 0x345adc/0x345ad8 -- the
        // actual D1 and D0 -- unnamed.
        Map<String, List<VtableScan.SubTable>> byClass = new LinkedHashMap<>();
        for (VtableScan.VtableGroup group : vtableScan.groups()) {
            if (group.kind() != VtableScan.Kind.CONSTRUCTION) continue;
            String cls = group.className();
            if (allVtableSlots.containsKey(cls)) continue;      // it has a table of its own
            if (classNamespaces.get(cls) == null) continue;
            VtableScan.SubTable primary = group.primary();
            if (!primary.isPrimary()) continue;                 // a B table is not the head
            byClass.computeIfAbsent(cls, k -> new ArrayList<>()).add(primary);
        }

        for (Map.Entry<String, List<VtableScan.SubTable>> e : byClass.entrySet()) {
            String className = e.getKey();
            List<VtableScan.SubTable> subs = e.getValue();
            subs.sort((a, b) -> b.slots().size() - a.slots().size());

            int inheritedDtorIdx = -1;
            List<String> parents = parentMap.get(className);
            if (parents != null && !parents.isEmpty()) {
                inheritedDtorIdx = dtorSlot.getOrDefault(parents.getFirst(), -1);
            }
            Set<Address> vtableWriters = collectVtableWriters(className);
            Set<String> used = new HashSet<>();
            boolean any = false;

            for (VtableScan.SubTable sub : subs) {
                List<Long> slots = sub.slots();
                String[] names = computeSlotNames(slots, sub.addressPoint(), 0,
                        vtableWriters, inheritedDtorIdx, className);

                for (int i = 0; i < slots.size(); i++) {
                    long raw = slots.get(i);
                    if (raw == 0) continue;
                    Address funcAddr = toAddress(raw & ~1L);
                    if (!className.equals(slotOwner.get(funcAddr.getOffset()))) continue;
                    // An adjustor thunk is not the class's method -- it stands in for one.
                    // The thunk machinery names those, with the _ZTv spelling that says so.
                    if (predictedThunks.containsKey(funcAddr.getOffset())) continue;
                    // One name per class: the tables agree on the slot layout, so the
                    // first one to claim a name is as good as any, and a second claim
                    // would put that name at a second address.
                    if (!used.add(names[i])) continue;

                    // Ghidra hands a forwarding stub its target's name and namespace, which
                    // is the wrong class and a second address for that symbol. Cut it loose
                    // first or the label below cannot stick.
                    Function func = program.getListing().getFunctionAt(funcAddr);
                    if (func != null && func.isThunk()) {
                        try {
                            func.setThunkedFunction(null);
                        } catch (Exception ex) {
                            // Leave it attached; nameForAbsentOwner will decline below.
                        }
                    }
                    int before = absentOwnerNamed;
                    namingFromCTable = true;
                    try {
                        nameForAbsentOwner(className, funcAddr, names[i], (raw & 1L) != 0);
                    } finally {
                        namingFromCTable = false;
                    }
                    if (absentOwnerNamed > before) {
                        constructionOnlyNamed++;
                        constructionOnlyAddrs.add(funcAddr);
                        any = true;
                    }
                }
            }
            if (any) constructionOnlyClasses++;
        }
    }

    /** Addresses named by the pass above, so emitMangledNames can reach them too. */
    private final Set<Address> constructionOnlyAddrs = new HashSet<>();

    private void processClass(String className) throws Exception {
        if (processed.contains(className)) return;
        processed.add(className);

        List<Long> mySlots = vtableSlots.get(className);
        if (mySlots == null) return;

        Namespace ns = classNamespaces.get(className);
        if (ns == null) {
            script.println("WARNING: No namespace found for " + className + ", skipping.");
            return;
        }

        // Label the primary vtable at its head -- the offset-to-top word _ZTV points
        // at, not the address point a vptr stores.
        Address addressPoint = vtableAddressPoints.get(className);
        Address labelAt = vtableHeads.getOrDefault(className, addressPoint);
        if (labelAt != null) {
            try {
                symTab.createLabel(labelAt, "vtable", ns, SourceType.USER_DEFINED);
            } catch (Exception e) {
                script.println("WARNING: Could not label vtable for " + className);
            }
        }

        // Where this class writes its own vtable pointers â€” the destructor tell.
        Set<Address> vtableWriters = collectVtableWriters(className);

        // Primary sub-vtable
        List<Long> parentSlots = null;
        List<String> parents = parentMap.get(className);
        if (parents != null && !parents.isEmpty()) {
            parentSlots = vtableSlots.get(parents.getFirst());
        }
        processSubVtable(className, ns, addressPoint, mySlots, parentSlots, 0, vtableWriters);

        // Secondary sub-vtables
        List<List<Long>> allSubVtables = allVtableSlots.get(className);
        if (allSubVtables == null || allSubVtables.size() <= 1) return;

        List<VtableScan.SubTable> subs = allVtableSubTables.get(className);
        List<Address> myAddressPoints = allVtableAddressPoints.get(className);
        List<String> positional = positionalBaseOrder(className, parents);

        for (int s = 1; s < allSubVtables.size(); s++) {
            Address secAddr = (myAddressPoints != null && s < myAddressPoints.size())
                    ? myAddressPoints.get(s) : null;

            String baseClassName = null;
            if (subs != null && s < subs.size()) {
                baseClassName = baseForSubTable(className, subs.get(s));
            }
            if (baseClassName == null) {
                // Nothing matched by offset: fall back to the old positional order.
                int p = s - 1;
                if (p < positional.size()) baseClassName = positional.get(p);
                subVtableByPosition++;
            } else {
                subVtableByOffset++;
            }

            List<Long> baseSlots = (baseClassName != null)
                    ? vtableSlots.get(baseClassName) : null;
            // A single-parent class inherits its secondaries from the parent's own
            // secondaries, so when the base resolves to that parent take the matching
            // sub-table rather than its primary.
            if (baseSlots != null && parents != null && parents.size() == 1
                    && parents.getFirst().equals(baseClassName)) {
                List<List<Long>> parentSubs = allVtableSlots.get(baseClassName);
                if (parentSubs != null && s < parentSubs.size()) baseSlots = parentSubs.get(s);
            }

            processSubVtable(className, ns, secAddr, allSubVtables.get(s), baseSlots, s,
                    vtableWriters);
        }
    }

    /**
     * Which base subobject a secondary sub-table serves, read off its offset-to-top
     * rather than guessed from its position.
     *
     * <p>A sub-table whose offset-to-top is -N serves the base sitting at byte offset N
     * in the complete object, so the answer is in {@code __base_class_type_info} already.
     * The positional order this replaces assumed the compiler emitted one sub-table per
     * base in declaration order, which breaks as soon as a base contributes none.
     * ClassLayoutBuilder.findSubVtable already matched by offset, so the two passes now
     * agree.
     */
    private String baseForSubTable(String className, VtableScan.SubTable sub) {
        int wanted = -sub.offsetToTop();
        if (wanted <= 0) return null;

        List<BaseRef> bases = baseInfoMap.get(className);
        if (bases != null) {
            String found = null;
            for (BaseRef b : bases) {
                if (b.isVirtual() || b.offset() != wanted) continue;
                if (found != null) return null;   // ambiguous; let the caller fall back
                found = b.name();
            }
            if (found != null) return found;
        }

        // A virtual base does not carry a byte offset of its own: its position is in the
        // vbase-offset words at the head of the primary sub-table.
        List<VtableScan.SubTable> subs = allVtableSubTables.get(className);
        if (subs == null || subs.isEmpty() || bases == null) return null;
        int[] vbaseOffsets = subs.get(0).vbaseOffsets();
        int index = -1;
        for (int i = 0; i < vbaseOffsets.length; i++) {
            if (vbaseOffsets[i] != wanted) continue;
            if (index >= 0) return null;          // two virtual bases at one offset
            index = i;
        }
        if (index < 0) return null;

        String found = null;
        int seen = 0;
        for (BaseRef b : bases) {
            if (!b.isVirtual()) continue;
            if (seen++ == index) found = b.name();
        }
        return found;
    }

    /** The old declaration-order expansion, kept as a fallback when no offset matches. */
    private List<String> positionalBaseOrder(String className, List<String> parents) {
        List<String> order = new ArrayList<>();
        if (parents == null) return order;
        if (parents.size() > 1) {
            for (int p = 1; p < parents.size(); p++) {
                expandBasesDepthFirst(parents.get(p), order);
            }
        } else if (parents.size() == 1) {
            order.add(parents.getFirst());
        }
        return order;
    }

    private void expandBasesDepthFirst(String baseClass, List<String> result) {
        result.add(baseClass);
        List<String> baseParents = parentMap.get(baseClass);
        if (baseParents != null && baseParents.size() > 1) {
            for (int i = 1; i < baseParents.size(); i++) {
                expandBasesDepthFirst(baseParents.get(i), result);
            }
        }
    }

    // ---------------------------------------------------------------
    //  Slot ownership: the least-derived class that lists a function
    // ---------------------------------------------------------------

    /** Function address (thumb bit cleared) -> the class that declares it. */
    private final Map<Long, String> slotOwner = new HashMap<>();

    private int ownersAssigned = 0;
    private int ownersContested = 0;
    private int slotsOwnedElsewhere = 0;

    /**
     * Decide, once and globally, which class each vtable slot target belongs to.
     *
     * <p>ARMCC points a slot the derived class does not override straight at the base's
     * own function, so one address appears in the tables of a whole chain of classes.
     * Naming it after whichever table reached it first is how {@code AcStrcCampingCar}
     * ended up owning methods of a class it does not even derive from. The function
     * belongs to the <em>least-derived</em> class that lists it -- that is where it was
     * declared; everyone below merely inherits it.
     *
     * <p>Construction vtables count as evidence here even though they never name anything.
     * They are the base's own table copied for a derived class's constructor, so they say
     * "this class lists this function" just as loudly as a real one -- and for a
     * construction table the class doing the listing is the one whose typeinfo it carries,
     * not the class it was emitted for. Seven of the eight tables naming
     * {@code AcObjectBase::D1} are construction tables; without them the evidence looks
     * like a single reference.
     *
     * <p>When the referencing classes do not form one chain, nothing is recorded. ARMCC
     * 4.1 has no identical-code folding, so one address really is one function belonging to
     * one class; a set that is not a chain means the walk went wrong somewhere, and
     * inventing an owner would bake that in.
     */
    private void assignSlotOwners() {
        if (vtableScan == null) return;

        Map<Long, Set<String>> referencedBy = new HashMap<>();
        for (VtableScan.VtableGroup group : vtableScan.groups()) {
            String owner = group.className();       // the typeinfo's class, always
            for (VtableScan.SubTable sub : group.subs()) {
                for (long raw : sub.slots()) {
                    if (raw == 0) continue;
                    long addr = raw & ~1L;
                    if (pureVirtualAddr != 0 && addr == (pureVirtualAddr & ~1L)) continue;
                    referencedBy.computeIfAbsent(addr, k -> new HashSet<>()).add(owner);
                }
            }
        }

        for (Map.Entry<Long, Set<String>> e : referencedBy.entrySet()) {
            int incompleteBefore = hierarchyIncomplete;
            String least = leastDerived(e.getValue());
            if (least == null) {
                ownersContested++;
                contestedTargets.add(e.getKey());
                if (hierarchyIncomplete > incompleteBefore) {
                    noAncestorExamples.add(describeRoots(e.getKey(), e.getValue()));
                }
                continue;
            }
            slotOwner.put(e.getKey(), least);
            ownersAssigned++;
            // The LCA is frequently a class with no vtable group of its own, so the walk
            // will never reach it to hand out a name. Record it for the naming pass.
            if (!e.getValue().contains(least)) ownersOutsideSet++;
        }
        script.printf("    Slot ownership:         %d targets assigned to their " +
                "least-derived class, %d contested and left alone\n",
                ownersAssigned, ownersContested);
        script.printf("                            %d owned by a class no referencing " +
                "table belongs to, %d with no shared ancestor in this image\n",
                ownersOutsideSet, hierarchyIncomplete);
        // Each of these is a function whose tables reach no common class -- in a complete
        // hierarchy, impossible -- so each names where the parent chains stop short.
        noAncestorExamples.sort(null);
        for (String ex : noAncestorExamples) script.println("        " + ex);
        rejectForeignRecoveredNames(referencedBy);
    }

    private final List<String> noAncestorExamples = new ArrayList<>();

    /**
     * Slot targets whose referencing classes have no single least common ancestor. Nobody
     * can be shown to own them, so nobody names them: the first class walked used to, which
     * is how 0x74de54 -- shared by sead::Thread, Heap, ExpHeap, FrameHeap and UnitHeap --
     * came out as sead::Thread::VF00_1, an owner that is not an ancestor of the others.
     */
    private final Set<Long> contestedTargets = new HashSet<>();

    /**
     * One line for a slot target with no shared ancestor: its referencing classes grouped
     * by the topmost class their known parent chain reaches.
     */
    private String describeRoots(long addr, Set<String> classes) {
        Map<String, List<String>> byRoot = new TreeMap<>();
        for (String c : classes) {
            Set<String> line = new HashSet<>(ancestorsOf(c));
            line.add(c);
            List<String> roots = new ArrayList<>();
            for (String a : line) {
                List<String> ps = parentMap.get(a);
                if (ps == null || ps.isEmpty()) roots.add(a);
            }
            roots.sort(null);
            byRoot.computeIfAbsent(String.join("+", roots), k -> new ArrayList<>()).add(c);
        }
        StringBuilder sb = new StringBuilder(String.format("0x%08x:", addr));
        for (Map.Entry<String, List<String>> r : byRoot.entrySet()) {
            List<String> members = r.getValue();
            members.sort(null);
            sb.append(String.format(" [chains stop at %s: %d class%s, e.g. %s]", r.getKey(),
                    members.size(), members.size() == 1 ? "" : "es", members.getFirst()));
        }
        return sb.toString();
    }

    /** Slot targets whose existing name names a class none of their referencers derive from. */
    private final Set<Long> foreignRecoveredNames = new HashSet<>();
    private int foreignNamesDropped = 0;
    private int foreignNamesKept = 0;

    /**
     * Throw out a recovered name whose class is a stranger to every table that references
     * the function.
     *
     * <p>{@code escape::BsEscapeModelPickupEvent::OnUnresolved} sat on {@code 0x7b1b88},
     * which 95 slots reference from classes with no path to it at all -- 95 of the 126
     * out-of-ancestry slot names the checker reports. armlink 4.1 folds no identical code
     * (open answers Q8), so one address is one function, and a function reached from a
     * class's vtable is declared by that class or by an ancestor of it. A name that
     * satisfies neither is on the wrong address; the right one is elsewhere, unreferenced.
     *
     * <p>How much is demanded of the name depends on whether the ancestry is known; see
     * the test below. Only <em>this</em> pass's labels are deleted -- an imported or
     * hand-written symbol is reported and left, since being unable to explain a name is
     * not evidence against the person who wrote it.
     */
    private void rejectForeignRecoveredNames(Map<Long, Set<String>> referencedBy) {
        // Keyed on the qualified name, not on the Namespace object: Ghidra hands out fresh
        // namespace instances per lookup, so a HashMap of them matched nothing at all and
        // this pass silently did nothing on its first run.
        Map<String, String> classOf = new HashMap<>();
        for (Map.Entry<String, Namespace> e : classNamespaces.entrySet()) {
            classOf.put(e.getValue().getName(true), e.getKey());
        }

        for (Map.Entry<Long, Set<String>> e : referencedBy.entrySet()) {
            Address addr = toAddress(e.getKey());
            // The unresolved-import handler is not a method. Dozens of CRO classes have a
            // slot pointing at it -- every import their module failed to resolve -- and one
            // of them, escape::BsEscapeModelPickupEvent, got its name onto it and from
            // there onto 66 slots and 192 import stubs. It is shared runtime code that
            // loads a string and returns; no class owns it.
            boolean handler = addr.equals(unresolvedImportHandler)
                    || addr.equals(unresolvedImportTail);
            Symbol named = null;
            String nameClass = null;
            for (Symbol s : symTab.getSymbols(addr)) {
                if (s.getName().startsWith("_Z") || isAutoLabel(s.getName())) continue;
                if (isPlaceholder(s.getName())) continue;
                Namespace owner = s.getParentNamespace();
                if (owner == null || owner.isGlobal()) continue;
                String cls = classOf.get(owner.getName(true));
                // On the handler, any class name is wrong, including one whose class this
                // image has never heard of. escape::BsEscapeModelPickupEvent's typeinfo
                // lives in a CRO, so requiring a known class let its name stay put.
                if (cls == null && !handler) continue;
                named = s;
                nameClass = (cls != null) ? cls : owner.getName(true);
                break;
            }
            if (nameClass == null) continue;

            // Only where the ancestry is known. slotOwner holds an entry exactly when the
            // referencing classes share an ancestor in this image; without one the chain
            // has left for a CRO whose typeinfo could not be read, and 78 of the 126
            // out-of-ancestry slot names are that -- correct names the image simply cannot
            // corroborate. A weaker floor was tried here and would have condemned them.
            //
            // Where the ancestry *is* known the name has to account for every referencing
            // table, because a function in class X's vtable is declared by X or by an
            // ancestor of X.
            if (!handler && !slotOwner.containsKey(e.getKey())) continue;
            boolean explains = !handler;
            for (String ref : e.getValue()) {
                if (!isAncestorOf(nameClass, ref)) { explains = false; break; }
            }
            if (explains) continue;

            foreignRecoveredNames.add(e.getKey());
            if (named.getSource() == SourceType.ANALYSIS) {
                named.delete();
                foreignNamesDropped++;
            } else {
                foreignNamesKept++;
            }
        }
        if (foreignNamesDropped > 0 || foreignNamesKept > 0) {
            script.printf("                            %d recovered names dropped as " +
                    "foreign to every referencing table, %d left in place (imported or " +
                    "hand-written) but not used\n", foreignNamesDropped, foreignNamesKept);
        }
    }

    // ---------------------------------------------------------------
    //  Thunk adjustments, predicted from where the slot sits
    // ---------------------------------------------------------------

    /** Function address -> the virtual adjustment its slot position says it applies. */
    private final Map<Long, ThunkAdjustment> predictedThunks = new HashMap<>();

    /** Function address -> the this-adjustment a non-virtual secondary sub-table implies. */
    private final Map<Long, Integer> secondaryAdjust = new HashMap<>();

    private int thunksPredicted = 0;
    private int thunksContested = 0;
    private int thunkBodyAgreed = 0;
    private int thunkBodyDisagreed = 0;
    /**
     * The two halves of {@link #thunkBodyDisagreed}, which measure different things and
     * were worth nothing added together. A vcall disagreement says the slot-position
     * formula and the instruction disagree about a virtual thunk -- a fault in the header
     * sizing or in {@code m}. An offset disagreement says a sub-table's offset-to-top is
     * not the constant the body subtracts, which is a fault in which base subobject the
     * sub-table was matched to. Examples are kept so the next run names the tables.
     */
    private int thunkVcallDisagreed = 0;
    private int thunkOffsetDisagreed = 0;
    private final List<String> thunkDisagreements = new ArrayList<>();
    private final Map<String, Integer> disagreementsByClass = new HashMap<>();

    private int placeholdersLeftUnmangled = 0;
    private int ownersOutsideSet = 0;
    private int hierarchyIncomplete = 0;
    private int absentOwnerNamed = 0;
    private static final int MAX_DISAGREEMENT_EXAMPLES = 6;

    /**
     * Work out each adjustor thunk's ABI numbers from the table it sits in, rather than by
     * reading its instructions.
     *
     * <p>ARMCC's thunk bodies vary too much to name from: the common form is
     * {@code LDR ; LDR ; ADD ; B}, but a D0 thunk that inlines the delete is 28 bytes with
     * the loads buried after a {@code PUSH}, a thunk to an empty function collapses to a
     * lone {@code BX lr} indistinguishable from any empty function, and under {@code -Otime}
     * a thunk inlines its target entirely. Reading the body answers "no thunk here" for all
     * three. That is why {@code AcObjectBase}'s destructor thunks came out unnamed while
     * the identically-shaped ones on either side of them in memory were fine.
     *
     * <p>The layout says it without ambiguity. A vcall word is non-zero exactly when its
     * slot holds a {@code _ZTv} thunk, and the vcall offset is simply how far that word
     * sits below the address point. So the run of header words is read off, and each
     * non-zero entry names a thunk and gives it its number.
     *
     * <p>The mapping from slot to header word runs backwards -- the run grows outward from
     * offset-to-top with the first virtual function nearest it -- and the D1/D0 pair shares
     * one word, which is what makes both destructor thunks come out {@code _ZTv0_n12_}.
     */
    private void predictThunkAdjustments() {
        if (vtableScan == null) return;

        // Every group, construction tables included. A class that declares a virtual base
        // may have no virtual-base sub-table of its own at all -- AcObjectBase does not --
        // and then the only tables describing that subobject are the _ZT_B1_ ones emitted
        // for the classes below it. Those are its layout, copied: the vcall words sit in
        // the same positions and so give the same m, only the values differ. Skipping them
        // is why its destructor thunks stayed unnamed while the formula was right.
        for (VtableScan.VtableGroup group : vtableScan.groups()) {
            for (VtableScan.SubTable sub : group.subs()) {
                if (sub.hasVcallOffsets()) {
                    predictVirtualThunks(sub);
                } else if (sub.offsetToTop() < 0) {
                    // A non-virtual secondary: every thunk in it shifts this by where the
                    // subobject sits, so the number is the same for all of them.
                    //
                    // Only slots this group's own class declares count. Most entries in a
                    // secondary are inherited functions that appear in the secondaries of
                    // a whole chain of classes, each at its own offset-to-top; taking the
                    // first table to mention one -- which is what this did -- is the exact
                    // first-visitor mistake the ownership pass exists to undo, and it is
                    // where the 105 cross-check disagreements came from.
                    for (long raw : sub.slots()) {
                        if (raw == 0) continue;
                        long addr = raw & ~1L;
                        if (!group.className().equals(slotOwner.get(addr))) continue;
                        if (!secondaryAdjust.containsKey(addr)) {
                            secondaryAdjust.put(addr, sub.offsetToTop());
                        } else {
                            Integer seen = secondaryAdjust.get(addr);
                            // Two of the class's own tables disagreeing on where the
                            // subobject sits leaves no defensible number, and a null entry
                            // keeps it that way against a later table that agrees with one
                            // of them by chance.
                            if (seen == null || seen != sub.offsetToTop()) {
                                secondaryAdjust.put(addr, null);
                            }
                        }
                    }
                }
            }
        }
        script.printf("    Thunk adjustments:      %d predicted from slot position, " +
                "%d contested between tables and left unpredicted\n",
                thunksPredicted, thunksContested);
    }

    /**
     * Name the destructor thunks that live only in construction vtables.
     *
     * <p>A class that declares a virtual base but has no virtual-base sub-table of its own
     * never has its {@code _ZTv} destructor thunks reached by the naming walk: the only
     * tables holding them are the {@code _ZT_B1_} ones emitted for classes below it, and
     * construction tables deliberately name nothing. So the functions were never even
     * created -- {@code AcObjectBase}'s pair sat at {@code LAB_00778604} and
     * {@code LAB_00778620} with no symbol at all, while its {@code D0} and {@code D1} four
     * words away were named.
     *
     * <p>Only the destructor pair is handled, because only it can be named without
     * guessing. Slots 0 and 1 of a virtual-base table are D1 and D0 -- that is already
     * encoded above, in the two of them sharing one vcall word -- and the class is the one
     * whose typeinfo the table carries. A later slot mirrors the <em>virtual base's</em>
     * vtable numbering rather than the owner's, so its target's name is not derivable here
     * and nothing is written for it.
     *
     * <p>The mangled thunk name goes on directly rather than through a
     * {@code Class::VF07}-style placeholder: a thunk is not a class method, and
     * {@code _ZTv} is ordinary Itanium that Ghidra demangles for display by itself.
     */
    private void nameOrphanDestructorThunks() {
        if (vtableScan == null) return;
        int named = 0;

        for (VtableScan.VtableGroup group : vtableScan.groups()) {
            Namespace ns = classNamespaces.get(group.className());
            if (ns == null) continue;
            for (VtableScan.SubTable sub : group.subs()) {
                if (!sub.hasVcallOffsets()) continue;
                for (int slot = 0; slot <= 1 && slot < sub.slots().size(); slot++) {
                    long raw = sub.slots().get(slot);
                    if (raw == 0) continue;
                    Address addr = program.getMinAddress().getAddressSpace()
                            .getAddress(raw & ~1L);
                    ThunkAdjustment adj = predictedThunks.get(addr.getOffset());
                    if (adj == null) continue;
                    // Only an existing _ZT* spelling counts as "already named". This used
                    // to skip anything carrying a real name at all, which left 41 slots
                    // holding an ordinary ~Class label and no thunk name -- the label came
                    // from a previous run's demangling, and it is not a substitute for the
                    // ABI name. The mangled name is a second symbol on the address, so
                    // adding it takes nothing away.
                    if (hasThunkName(addr)) continue;

                    String target = mangle(ns, (slot == 0) ? "D1" : "D0");
                    if (target == null) continue;
                    ensureFunction(addr, (raw & 1L) != 0);
                    if (bodySaysNonVirtual(addr)) {
                        noteThunkKindConflict(group, sub, addr);
                        continue;
                    }
                    if (MangledNames.addMangled(script, program, addr,
                            asThunk(target, adj))) {
                        named++;
                        virtualThunkCount++;
                    }
                }
            }
        }
        if (named > 0) {
            script.printf("    Orphan thunks:          %d destructor thunks named that " +
                    "only construction vtables reach\n", named);
        }
    }

    private int thunkKindConflicts = 0;
    private final List<String> thunkKindConflictExamples = new ArrayList<>();

    private static final java.util.regex.Pattern VPTR_LOAD =
            java.util.regex.Pattern.compile("ldr (r\\d+),\\[r0(,#0x0)?\\]");
    private static final java.util.regex.Pattern CONST_ADJUST =
            java.util.regex.Pattern.compile("(sub|add) r0,r0,#0x[0-9a-f]+");

    /**
     * Whether a thunk's first instructions adjust {@code this} by a constant without ever
     * loading through the vptr. A virtual thunk cannot do that: its adjustment is a vcall
     * offset read out of the vtable at a negative displacement, which no optimisation can
     * fold away because its value depends on the complete object. (The adjustment *amount*
     * can be folded -- the fixes doc's rule against validating n -- but not its kind.)
     * MusFish's 0x1aef8 is "sub r0,r0,#0xd0 ... b D0": non-virtual, named _ZTv0_n12_.
     */
    private boolean bodySaysNonVirtual(Address entry) {
        boolean constAdjust = false;
        Address a = entry;
        for (int i = 0; i < 6 && a != null; i++) {
            Instruction ins = program.getListing().getInstructionAt(a);
            if (ins == null) break;
            String text = ins.toString().toLowerCase();
            if (VPTR_LOAD.matcher(text).find()) return false;
            if (CONST_ADJUST.matcher(text).find()) constAdjust = true;
            if (ins.getFlowType().isJump() || ins.getFlowType().isTerminal()) break;
            a = ins.getMaxAddress().next();
        }
        return constAdjust;
    }

    private void noteThunkKindConflict(VtableScan.VtableGroup group, VtableScan.SubTable sub,
                                       Address addr) {
        thunkKindConflicts++;
        if (thunkKindConflictExamples.size() >= MAX_DISAGREEMENT_EXAMPLES) return;
        StringBuilder words = new StringBuilder();
        for (int w : sub.vbaseOffsets()) words.append(w).append(' ');
        thunkKindConflictExamples.add(String.format("%s: group %s (%s%s) sub-table at %s, " +
                        "offset-to-top %d, header [%s] of which %d vbase", addr,
                group.className(), group.kind(),
                group.derivedOwner() == null ? "" : " for " + group.derivedOwner(),
                sub.head(), sub.offsetToTop(), words.toString().trim(), sub.vbaseWords()));
    }

    /** True when an ABI thunk spelling is already on this address. */
    private boolean hasThunkName(Address addr) {
        for (Symbol s : symTab.getSymbols(addr)) {
            String name = s.getName();
            if (name.startsWith("_ZTv") || name.startsWith("_ZTh")) return true;
        }
        return false;
    }

    /** True when something other than Ghidra's own default label already names this. */
    private boolean hasRealName(Address addr) {
        for (Symbol s : symTab.getSymbols(addr)) {
            if (s.getSource() == SourceType.DEFAULT) continue;
            if (!s.getParentNamespace().isGlobal()) return true;
            if (s.getName().startsWith("_Z")) return true;
        }
        return false;
    }

    private void predictVirtualThunks(VtableScan.SubTable sub) {
        int words = sub.vbaseCount();
        for (int slot = 0; slot < sub.slots().size(); slot++) {
            // Slots 0 and 1 are the destructor pair and share the word nearest
            // offset-to-top; every later slot steps one word further out.
            int i = (slot <= 1) ? words - 1 : words - slot;
            if (i < 0 || i >= words) continue;
            if (sub.vbaseOffsets()[i] == 0) continue;   // not overridden, so not a thunk

            long raw = sub.slots().get(slot);
            if (raw == 0) continue;
            // m is the byte distance of the vcall word below the address point.
            int m = PTR_SIZE * (words + 2 - i);
            long addr = raw & ~1L;
            ThunkAdjustment seen = predictedThunks.get(addr);
            if (seen == null) {
                if (predictedThunks.containsKey(addr)) continue;   // already contested
                predictedThunks.put(addr, new ThunkAdjustment(0, -m));
                thunksPredicted++;
            } else if (seen.vcallOffset() != -m) {
                // Two tables put the same thunk at different vcall offsets. One of them is
                // mis-sized, and writing either number would look authoritative.
                predictedThunks.put(addr, null);
                thunksPredicted--;
                thunksContested++;
            }
        }
    }

    /**
     * Reconcile what the layout predicts with what the body reads, preferring the layout.
     *
     * <p>The body is kept as a cross-check because it is an independent measurement: when
     * a thunk is in the common form its {@code #-m} has to be the number the table implies,
     * and a disagreement means one of the two models is wrong about this table.
     */
    private ThunkAdjustment chooseAdjustment(Address funcAddr, ThunkAdjustment body) {
        ThunkAdjustment predicted = predictedThunks.get(funcAddr.getOffset());
        if (predicted != null) {
            if (body != null && body.isVirtual()) {
                if (body.vcallOffset().equals(predicted.vcallOffset())) thunkBodyAgreed++;
                else {
                    thunkBodyDisagreed++;
                    thunkVcallDisagreed++;
                    noteDisagreement(funcAddr, String.format("vcall %s: table %d, body %d",
                            funcAddr, predicted.vcallOffset(), body.vcallOffset()));
                }
            }
            return predicted;
        }
        // The table, not the body. Under -Otime a thunk inlines the function it forwards
        // to, so its body carries that function's constants as well as its own
        // adjustment, and the first one encountered is not reliably the adjustment.
        // The table's offset-to-top is what the name's number means, and it is read
        // rather than decoded.
        Integer at = secondaryAdjust.get(funcAddr.getOffset());
        if (at != null) {
            // The cross-check now asks the answerable question: does the body apply this
            // adjustment *somewhere*? A body that never touches this by -ott is one the
            // layout model has mis-assigned; a body that does, plus other constants, is
            // just an inlined one.
            Set<Integer> constants = bodyConstantCache.get(funcAddr.getOffset());
            if (constants != null && !constants.isEmpty()) {
                if (constants.contains(at)) {
                    thunkBodyAgreed++;
                } else {
                    thunkBodyDisagreed++;
                    thunkOffsetDisagreed++;
                    noteDisagreement(funcAddr, String.format(
                            "offset %s: table %d, body applies %s", funcAddr, at, constants));
                }
            }
            return new ThunkAdjustment(at, null);
        }
        return body;
    }

    /**
     * The cross-check's detail, printed directly under the line it belongs to.
     *
     * <p>Grouped by class first, because that is what says whether a disagreement is a
     * broken model or a broken class: 18 spread as 2 apiece across 9 classes is nine
     * destructor pairs, not a systematic fault.
     */
    private void reportThunkDisagreements() {
        disagreementsByClass.entrySet().stream()
                .sorted((a, b) -> b.getValue() - a.getValue())
                .limit(8)
                .forEach(e -> script.printf("                            %d in %s\n",
                        e.getValue(), e.getKey()));
        for (String detail : thunkDisagreements) {
            script.printf("                            %s\n", detail);
        }
    }

    private void noteDisagreement(Address funcAddr, String detail) {
        if (thunkDisagreements.size() < MAX_DISAGREEMENT_EXAMPLES) {
            thunkDisagreements.add(detail);
        }
        // Twelve raw lines said "widespread" when the truth was "one class, every slot".
        // Counting by owner is what distinguishes a broken model from a broken class.
        String owner = slotOwner.get(funcAddr.getOffset());
        disagreementsByClass.merge(owner == null ? "(unowned)" : owner, 1, Integer::sum);
    }

    /**
     * The least common ancestor of every class whose table references one address: the
     * most-derived class that is an ancestor-or-self of all of them.
     *
     * <p>This used to pick the most-derived <em>member of the set</em>, which is only the
     * right answer when the declaring class happens to have a vtable group of its own. In
     * 40 of 44 measured cases it does not -- an abstract base whose constructors are all
     * inlined loses its {@code _ZTV} to unused-section elimination, so the walk never
     * visits it and the name lands on whichever subclass was seen first. That is how
     * {@code 0x525014} came out as {@code ElmFieldBuilder::VF03} when it is referenced by
     * five builders whose only shared ancestor is {@code BasicBuilder}, which has no table
     * at all.
     *
     * <p>The answer is a <em>lower bound</em>: the real declarer is this class or one of
     * its ancestors, because a base that declares a virtual and a base that merely
     * inherits it are indistinguishable from the tables alone. It is the most specific
     * name the data proves, which is the most that should be claimed.
     *
     * <p>Null when the classes share no ancestor in this image. That means the chain
     * leaves for a CRO whose typeinfo was never scanned, not that the walk is wrong, so
     * the caller leaves the existing name alone rather than inventing one.
     */
    private String leastDerived(Set<String> classes) {
        if (classes.size() == 1) return classes.iterator().next();

        Set<String> common = null;
        for (String c : classes) {
            Set<String> selfAndAncestors = new HashSet<>(ancestorsOf(c));
            selfAndAncestors.add(c);
            if (common == null) common = selfAndAncestors;
            else common.retainAll(selfAndAncestors);
            if (common.isEmpty()) break;
        }
        if (common == null || common.isEmpty()) {
            hierarchyIncomplete++;
            return null;
        }

        // The most-derived member of the common set: the one every other member is an
        // ancestor of. A well-formed ancestor set is a chain, so there is exactly one.
        String best = null;
        for (String candidate : common) {
            Set<String> above = ancestorsOf(candidate);
            boolean belowAll = true;
            for (String other : common) {
                if (other.equals(candidate)) continue;
                if (!above.contains(other)) { belowAll = false; break; }
            }
            if (belowAll) {
                if (best != null) return null;   // two incomparable candidates
                best = candidate;
            }
        }
        return best;
    }

    private boolean isAncestorOf(String potentialAncestor, String className) {
        Set<String> visited = new HashSet<>();
        List<String> toCheck = new ArrayList<>();
        toCheck.add(className);
        while (!toCheck.isEmpty()) {
            String current = toCheck.removeLast();
            if (visited.contains(current)) continue;
            visited.add(current);
            if (current.equals(potentialAncestor)) return true;
            List<String> parents = parentMap.get(current);
            if (parents != null) toCheck.addAll(parents);
        }
        return false;
    }

    private String findCommonAncestor(String classA, String classB) {
        Set<String> ancestorsA = new HashSet<>();
        List<String> toCheck = new ArrayList<>();
        toCheck.add(classA);
        while (!toCheck.isEmpty()) {
            String current = toCheck.removeLast();
            if (ancestorsA.contains(current)) continue;
            ancestorsA.add(current);
            List<String> parents = parentMap.get(current);
            if (parents != null) toCheck.addAll(parents);
        }

        ArrayDeque<String> bfsQueue = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        bfsQueue.add(classB);
        while (!bfsQueue.isEmpty()) {
            String current = bfsQueue.poll();
            if (visited.contains(current)) continue;
            visited.add(current);
            if (ancestorsA.contains(current)) return current;
            List<String> parents = parentMap.get(current);
            if (parents != null) bfsQueue.addAll(parents);
        }
        return null;
    }

    private boolean callsOperatorDelete(Address funcAddr) {
        return callsOperatorDelete(funcAddr, new HashSet<>(), 2);
    }

    /**
     * A deleting destructor calls operator delete. A secondary slot holds a thunk to
     * the real D0 rather than D0 itself, so hand-offs are followed one level further.
     */
    private boolean callsOperatorDelete(Address funcAddr, Set<Address> visited, int depth) {
        if (depth < 0 || !visited.add(funcAddr)) return false;
        try {
            Function func = program.getListing().getFunctionAt(funcAddr);
            if (func == null) return false;

            InstructionIterator iter =
                    program.getListing().getInstructions(func.getBody(), true);
            while (iter.hasNext()) {
                Instruction inst = iter.next();
                FlowType flow = inst.getFlowType();
                if (!flow.isCall() && !flow.isJump() && !flow.isTerminal()) continue;
                for (Reference ref : inst.getReferencesFrom()) {
                    Address target = ref.getToAddress();
                    if (target == null) continue;
                    if (operatorDeleteAddrs.contains(target.getOffset() & ~1L)) return true;
                    for (Symbol sym : symTab.getSymbols(target)) {
                        if (isOperatorDelete(sym.getName())) return true;
                        if (isDeletingDestructorName(sym.getName())) return true;
                    }
                    // Only out of an adjustor stub: chasing every call would walk most
                    // of the program, and mistake a member-destroying D1 for a thunk.
                    if (isThunkSized(func) && !func.getBody().contains(target)
                            && callsOperatorDelete(target, visited, depth - 1)) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            // fall through
        }
        return false;
    }

    private final Map<Address, Boolean> deallocatorTailCache = new HashMap<>();

    /**
     * Whether a function's <em>last</em> instruction hands control to a deallocator.
     *
     * <p>This is what separates D0 from every other slot. armcc's deleting destructor
     * destroys and then frees, and the free is the last thing it does, so it ends in
     * {@code B _ZdlPv} (or {@code BL} then a return, when the body could not tail-call).
     * Nothing else in a vtable ends that way: a D1 that frees a member reaches operator
     * delete too, but in the middle of its body, not off its tail -- which is why
     * {@link #callsOperatorDelete}, asking only "does it reach it at all", could not tell
     * the two apart and the pair was being placed by index instead.
     *
     * <p>Two indirections have to be followed to see the tail at all:
     * <ul>
     * <li>a one-instruction {@code B} stub, which armlink leaves behind when it splits a
     *     tail call out of its section;</li>
     * <li>a trailing {@code MOV r0,r0}, which is {@code --branchnop}'s rewrite of a branch
     *     to the very next address (open answers Q6b). The function then ends by falling
     *     into whatever follows it, and that is where the deallocator call lives.</li>
     * </ul>
     */
    private boolean endsInDeallocator(Address funcAddr) {
        if (funcAddr == null) return false;
        Boolean cached = deallocatorTailCache.get(funcAddr);
        if (cached != null) return cached;
        boolean result = endsInDeallocator(funcAddr, new HashSet<>(), 3);
        deallocatorTailCache.put(funcAddr, result);
        return result;
    }

    private boolean endsInDeallocator(Address funcAddr, Set<Address> visited, int depth) {
        if (funcAddr == null || depth < 0 || !visited.add(funcAddr)) return false;
        if (operatorDeleteAddrs.contains(funcAddr.getOffset() & ~1L)) return true;
        try {
            Function func = program.getListing().getFunctionAt(funcAddr);
            if (func == null) return false;
            Instruction last = null;
            InstructionIterator back =
                    program.getListing().getInstructions(func.getBody(), false);
            if (back.hasNext()) last = back.next();
            if (last == null) return false;

            if (last.getLength() == 4 && mem.getInt(last.getAddress()) == 0xe1a00000) {
                Address next = last.getAddress().add(4);
                return isShortHop(next) && endsInDeallocator(next, visited, depth - 1);
            }
            FlowType flow = last.getFlowType();
            if (!flow.isCall() && !flow.isJump() && !flow.isTerminal()) return false;
            for (Reference ref : last.getReferencesFrom()) {
                Address target = ref.getToAddress();
                if (target == null) continue;
                if (operatorDeleteAddrs.contains(target.getOffset() & ~1L)) return true;
                for (Symbol sym : symTab.getSymbols(target)) {
                    if (isOperatorDelete(sym.getName())) return true;
                }
                // A branch back inside this body is a loop, not a hand-off.
                if (func.getBody().contains(target)) continue;
                // Only step through something small enough to be a stub or a veneer. A
                // chain of full-sized helpers that eventually frees is an ordinary
                // Destroy()-style method, not a deleting destructor, and following one
                // would hand the D0 name to whichever slot happens to call it.
                if (!isShortHop(target)) continue;
                if (endsInDeallocator(target, visited, depth - 1)) return true;
            }
        } catch (Exception e) {
            // Unreadable or undisassembled: no evidence either way.
        }
        return false;
    }

    /**
     * Cut loose the Ghidra thunks that are really pieces of the function before them.
     *
     * <p>Ghidra splits a function out wherever a conditional branch lands on an address it
     * decides to treat as an entry -- {@code 0x586104} is a {@code beq} target inside
     * {@code 0x5860c0}, and it starts with the {@code NOP} {@code --branchnop} leaves
     * behind (open answers Q6b). When it also marks the piece a thunk of its parent, the
     * piece reports the parent's name <em>and namespace</em>, so the parent's symbol --
     * mangled spelling included -- comes out at a second address. That is where the
     * remaining {@code D1Ev} duplicates come from; this pass never wrote them, and the
     * one-name-one-address guard in {@link #emitMangledNames} cannot see them, because it
     * only plans names for addresses a vtable slot points at.
     *
     * <p>The test is deliberately narrow: every reference to the address has to be flow,
     * and all of it from inside the function it sits in the middle of. A single data
     * reference -- a vtable slot, a function pointer, a jump table -- means something
     * outside treats it as an entry point, and then it is one. Detaching leaves it as
     * {@code FUN_}, which is what it should have been.
     */
    private void detachMirroringFragments() {
        int detached = 0;
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (!func.isThunk()) continue;
            Address entry = func.getEntryPoint();
            if (allSlotTargets.contains(entry.getOffset() & ~1L)) continue;
            if (entry.getOffset() == 0) continue;

            Function prev;
            try {
                prev = program.getListing().getFunctionContaining(entry.subtract(1));
            } catch (Exception e) {
                continue;
            }
            if (prev == null || prev.equals(func)) continue;

            boolean reached = false;
            boolean fragment = true;
            for (Reference ref : program.getReferenceManager().getReferencesTo(entry)) {
                if (!ref.getReferenceType().isFlow()
                        || !prev.getBody().contains(ref.getFromAddress())) {
                    fragment = false;
                    break;
                }
                reached = true;
            }
            if (!fragment || !reached) continue;
            try {
                func.setThunkedFunction(null);
                detached++;
            } catch (Exception e) {
                // Leave it attached rather than half-detached.
            }
        }
        if (detached > 0) {
            script.printf("    Function fragments:     %d cut loose from the function they " +
                    "sit inside, so its name stops appearing at their address too\n",
                    detached);
        }
    }

    /**
     * Cut loose every Ghidra thunk that forwards to {@code target}.
     *
     * <p>Ghidra gives a thunk its target's name <em>and namespace</em>, so the moment a
     * runtime function gets a real name, every one-instruction {@code B} stub that reaches
     * it starts reporting that name too -- and the export, which sees one name at two
     * addresses, suffixes the second. Labelling {@code 0x2f88b8} as {@code _ZdaPv} put
     * {@code _ZdaPv_00313ac8} on the Base family's own class delete, which is a different
     * function whose name is not recoverable at all.
     *
     * <p>Detaching leaves the stub as {@code FUN_}, which is the honest answer: armcc
     * never emitted a symbol for it.
     */
    private void detachThunksTo(Address target) {
        if (target == null) return;
        Function f = program.getListing().getFunctionAt(target);
        if (f == null) return;
        Address[] thunks = f.getFunctionThunkAddresses();
        if (thunks == null) return;
        for (Address a : thunks) {
            Function t = program.getListing().getFunctionAt(a);
            if (t == null || !t.isThunk()) continue;
            try {
                t.setThunkedFunction(null);
            } catch (Exception e) {
                // Leave it attached rather than half-detached.
            }
        }
    }

    /** Bytes at or under which a function is a hop -- a branch stub or a linker veneer. */
    private static final int SHORT_HOP_BYTES = 12;

    private boolean isShortHop(Address addr) {
        if (addr == null) return false;
        if (operatorDeleteAddrs.contains(addr.getOffset() & ~1L)) return true;
        Function f = program.getListing().getFunctionAt(addr);
        return f != null && f.getBody().getNumAddresses() <= SHORT_HOP_BYTES;
    }

    /** Ghidra's label for operator delete, or its mangled spellings (_ZdlPv, _ZdaPv, ...). */
    private static boolean isOperatorDelete(String name) {
        return name.startsWith("operator.delete")
                || name.startsWith("_Zdl") || name.startsWith("_Zda");
    }

    /** A deleting-destructor name this script has already handed out: D0 or D0_<sub>. */
    private static boolean isDeletingDestructorName(String name) {
        return name.equals("D0") || name.startsWith("D0_");
    }

    private Namespace createNamespace(Program program, Namespace parent, String name) throws Exception {
        return program.getSymbolTable()
                .createNameSpace(parent, name, SourceType.USER_DEFINED);
    }

    /**
     * Name every slot of a sub-vtable: D1/D0 for the destructor pair, VF02 onward for
     * the rest, so 00 and 01 stay reserved for that pair.
     *
     * D1 is the only function in a vtable that writes its own vtable pointer back
     * into this (a constructor does too, but is never virtual), and the ABI puts D0
     * in the next slot. Where optimisation elided those stores, the primary vtable
     * still preserves the base's slot ordering, so the index the base used carries
     * down the hierarchy.
     */
    private String[] computeSlotNames(List<Long> mySlots, Address start, int subIdx,
                                      Set<Address> vtableWriters, int inheritedDtorIdx,
                                      String className)
            throws MemoryAccessException {
        AddressSpace addressSpace = program.getMinAddress().getAddressSpace();
        int n = mySlots.size();
        String[] kind = new String[n];      // "D0", "D1", or null for an ordinary slot

        // Every slot is a candidate: declaration order puts the destructor wherever it
        // was declared. Address order decides between them further down.
        for (int i = 0; i < n; i++) {
            long funcPtr = mySlots.get(i);
            if (funcPtr == 0) continue;
            if (start != null && isPureVirtualRef(start.add(4L * i))) continue;
            Address funcAddr = addressSpace.getAddress(funcPtr & ~1L);

            // Operator delete goes last: a D1 that frees a member reaches it too, so
            // on its own it cannot tell D1 from D0.
            String thunked;
            if (writesOwnVtable(funcAddr, vtableWriters)) { kind[i] = "D1"; dtorByWrite++; }
            else if ((thunked = thunkedDestructorKind(funcAddr)) != null) {
                kind[i] = thunked; dtorByThunk++;
            }
            else if (callsOperatorDelete(funcAddr)) { kind[i] = "D0"; dtorByDelete++; }
            // Last, and only once the stores have had their say: running the bases'
            // destructors is what a destructor does after them.
            else if (callsAncestorDestructor(funcAddr, className)) {
                kind[i] = "D1";
                dtorByBaseCall++;
            }
        }

        // Nothing at the base's destructor index means the stores were elided here.
        if (inheritedDtorIdx >= 0 && inheritedDtorIdx < n
                && kind[inheritedDtorIdx] == null) {
            kind[inheritedDtorIdx] = "D1";
            dtorByInherit++;
        }
        boolean found = false;
        for (String k : kind) if (k != null) { found = true; break; }
        if (!found && n > 0) dtorNone++;

        if (subIdx == 0 && hasPureVirtualDestructor(className, mySlots)) {
            Arrays.fill(kind, null);
            pureDestructors++;
        } else {
            chooseDestructorPair(kind, mySlots, (subIdx == 0) ? inheritedDtorIdx : -1);
        }

        String[] names = new String[n];
        for (int i = 0; i < n; i++) {
            String base = (kind[i] != null) ? kind[i] : String.format("VF%02d", i);
            // A secondary sub-vtable repeats the slot numbers of the primary, so its
            // names carry the sub-vtable index to stay distinct within the class.
            names[i] = (subIdx == 0) ? base : String.format("%s_%d", base, subIdx);
        }
        return names;
    }

    /**
     * A sub-vtable has exactly one destructor pair, so any further pair is a false
     * positive. Both extra halves are demoted back to ordinary slots.
     *
     * What produces them: writesOwnVtable only asks whether the function body
     * references one of the class's vtable address points, which a clone or factory
     * does as well -- it allocates, then stores the vtable pointer into the object it
     * just built rather than into this. That reads exactly like a destructor storing
     * its own vtable, so a second D1/D0 pair appears further down the vtable (the
     * "1010" pattern: D1, D0, D1, D0).
     *
     * The earliest pair survives, whether it was detected or filled in from the base's
     * index. A destructor sits at the index its base established and bases are laid
     * out first, so anything a derived class adds -- a clone among them -- comes after
     * it. Position is the one signal that holds when the evidence on both pairs looks
     * alike: preferring a detected later pair over a filled-in earlier one loses
     * whenever the stores in the real destructor were elided and a clone further down
     * was recognised instead.
     */
    private void chooseDestructorPair(String[] kind, List<Long> slots, int inheritedIdx) {
        int n = kind.length;

        // Where a pair could start. The pair is D1 then D0 in adjacent slots, so a half
        // recognised as D0 puts the start one slot earlier, and a D1 on the last slot has
        // no room for its D0 and cannot be a pair start at all.
        TreeSet<Integer> starts = new TreeSet<>();
        for (int d = 0; d < n; d++) {
            if (kind[d] == null) continue;
            int start = "D0".equals(kind[d]) ? d - 1 : d;
            if (start >= 0 && start + 1 < n) starts.add(start);
            else dtorTrailingDropped++;
        }
        // Also every pair whose bodies differ by one call, whether or not a heuristic
        // fired on it. The heuristics look at one slot at a time and can miss the pair
        // entirely while firing on a neighbour, which is how a three-slot vtable ended up
        // named D1, D0, ordinary when the truth was ordinary, D1, D0.
        for (int i = 0; i + 1 < n; i++) {
            Address d1 = slotTarget(slots, i);
            Address d0 = slotTarget(slots, i + 1);
            if (d1 != null && d0 != null && extraCall(d1, d0) != null) starts.add(i);
        }
        for (int i = 0; i < n; i++) kind[i] = null;

        // The deallocating tail outranks everything below, because it is not a heuristic:
        // armcc's D0 ends in a deallocator and no other slot does. Where any slot in this
        // table qualifies, the pair is (that slot - 1, that slot) and the scoring never
        // runs. Measured on ACNL: 1,334 of 1,518 D0 names already ended in one, and of the
        // rest the real deallocating slot sat +1, -1, -2, even -37 slots from where the
        // index-based pick had put the pair.
        //
        // This is built over every slot, not over `starts`: the whole failure is that the
        // heuristics did not propose the right slot, so filtering their proposals could
        // not have recovered it.
        TreeSet<Integer> deleting = new TreeSet<>();
        for (int i = 1; i < n; i++) {
            if (slotTarget(slots, i - 1) == null) continue;
            Address d0 = slotTarget(slots, i);
            if (d0 != null && endsInDeallocator(d0)) deleting.add(i - 1);
        }
        boolean byDeallocTail = !deleting.isEmpty();
        if (byDeallocTail) {
            starts = deleting;
            dtorByDeallocTail++;
        } else if (!starts.isEmpty()) {
            // The doc's rule is to emit neither name here. Falling back to the scoring
            // instead, and counting it, keeps the classes whose D0 Ghidra never
            // disassembled (or whose slot is __cxa_pure_virtual) from silently losing
            // their destructor -- but every pair in this count rests on shape and address
            // alone, so it is the right place to look when one is wrong.
            dtorNoDeallocTail++;
        }
        if (starts.isEmpty()) return;

        // The destructor's index is fixed by the root of the hierarchy, not by the class
        // being looked at: a derived class can overwrite an inherited slot or append new
        // ones, but it cannot move anything. So when the base put its pair at an index
        // that is a candidate here too, that is the answer, and the scoring below -- which
        // otherwise prefers whichever pair sits highest in memory -- does not get a say.
        // Without this a clone or factory further down the vtable, which also stores a
        // vtable pointer into the object it builds, wins on address and takes the name.
        if (inheritedIdx >= 0 && starts.contains(inheritedIdx)
                && slotTarget(slots, inheritedIdx) != null
                && slotTarget(slots, inheritedIdx + 1) != null) {
            kind[inheritedIdx] = "D1";
            kind[inheritedIdx + 1] = "D0";
            dtorExtraPairs += starts.size() - 1;
            dtorByInheritedIndex++;
            return;
        }

        int chosen = -1;
        Address chosenD1 = null;
        int chosenScore = -1;
        for (int start : starts) {
            Address d1 = slotTarget(slots, start);
            Address d0 = slotTarget(slots, start + 1);
            if (d1 == null || d0 == null) continue;

            // Two independent signals, strongest first. Shape: D0 is D1 plus one call,
            // which nothing else in a vtable looks like. Order: D0Ev sorts before D1Ev,
            // so the deleting destructor sits immediately below the complete one -- a
            // clone or factory pair, the usual false positive since it stores a vtable
            // pointer into the object it builds, has no reason to land that way round.
            int score = (extraCall(d1, d0) != null ? 2 : 0)
                    + (d0.compareTo(d1) < 0 ? 1 : 0);
            if (chosen >= 0) {
                if (score < chosenScore) continue;
                if (score == chosenScore) {
                    // Which way to break a tie depends on what put these candidates here.
                    //
                    // Every candidate deallocates: the losers are not clones -- a clone
                    // allocates -- but other slots that free, a Destroy() or a Dispose().
                    // A class has exactly one destructor pair, and its index is fixed by
                    // the root of the hierarchy, so it is the *earliest* of them; anything
                    // the class added itself comes after. Actor's real pair sits at slot 0
                    // and a second freeing pair at slot 5, and preferring the higher
                    // address handed the name to slot 5.
                    //
                    // With no deallocating slot the candidates came from shape and stores,
                    // where the usual false positive is a clone or factory -- it stores a
                    // vtable pointer into the object it builds, which reads like a
                    // destructor -- and both destructors sort after every other member, so
                    // there the real one is furthest into the class's run.
                    if (byDeallocTail) continue;
                    if (d1.compareTo(chosenD1) <= 0) continue;
                }
            }
            chosen = start;
            chosenD1 = d1;
            chosenScore = score;
        }
        if (chosen < 0) return;

        kind[chosen] = "D1";
        kind[chosen + 1] = "D0";
        dtorExtraPairs += starts.size() - 1;
        if ((chosenScore & 2) != 0) dtorByShape++;
        if ((chosenScore & 1) == 0) dtorUnordered++;
    }

    /** Call targets outside the function's own body, in body order. */
    private List<Address> callTargets(Address funcAddr) {
        List<Address> cached = callTargetCache.get(funcAddr);
        if (cached != null) return cached;

        List<Address> targets = new ArrayList<>();
        Function func = program.getListing().getFunctionAt(funcAddr);
        if (func != null) {
            try {
                InstructionIterator iter =
                        program.getListing().getInstructions(func.getBody(), true);
                while (iter.hasNext()) {
                    Instruction inst = iter.next();
                    if (!inst.getFlowType().isCall()) continue;
                    for (Reference ref : inst.getReferencesFrom()) {
                        Address target = ref.getToAddress();
                        if (target == null || func.getBody().contains(target)) continue;
                        targets.add(target);
                        break;
                    }
                }
            } catch (Exception e) { /* a partial list still discriminates */ }
        }
        callTargetCache.put(funcAddr, targets);
        return targets;
    }

    /**
     * The one call the second function makes that the first does not, or null if they
     * differ by anything else.
     *
     * A deleting destructor is the complete one with a deallocation added. It need not
     * call D1 -- armcc emits the body twice -- but it is otherwise the same code, so its
     * calls are D1's calls with exactly one extra, in order. That extra call is operator
     * delete, which is how this finds the pair and the deallocator together without
     * knowing either up front.
     */
    private Address extraCall(Address d1, Address d0) {
        return singleExtra(callTargets(d1), callTargets(d0));
    }

    /**
     * The one element {@code more} has that {@code fewer} does not, keeping order, or null
     * if they differ by anything else.
     */
    static <T> T singleExtra(List<T> fewer, List<T> more) {
        if (more.size() != fewer.size() + 1) return null;

        T extra = null;
        for (int i = 0, j = 0; j < more.size(); j++) {
            if (i < fewer.size() && fewer.get(i).equals(more.get(j))) {
                i++;
                continue;
            }
            if (extra != null) return null;         // more than one difference
            extra = more.get(j);
        }
        return extra;
    }

    /**
     * Find operator delete from the shape of the destructor pairs themselves, for programs
     * whose symbol table never named it.
     *
     * An earlier attempt to infer it from everything deleting destructors call failed:
     * teardown runs through a chain of helpers all reached by the same classes, so
     * agreement could not single out the deallocator. This asks a far narrower question --
     * of two adjacent slots whose bodies differ by exactly one call, what is that call --
     * and the answer agrees across unrelated classes only for operator delete.
     */
    private void detectOperatorDelete() {
        Map<Address, Integer> tally = new HashMap<>();
        for (List<List<Long>> subVtables : allVtableSlots.values()) {
            for (List<Long> slots : subVtables) {
                for (int i = 0; i + 1 < slots.size(); i++) {
                    Address d1 = slotTarget(slots, i);
                    Address d0 = slotTarget(slots, i + 1);
                    if (d1 == null || d0 == null) continue;
                    Address extra = extraCall(d1, d0);
                    if (extra != null) tally.merge(extra, 1, Integer::sum);
                }
            }
        }

        // Every candidate near the winner, not just the winner itself. ACNL links one
        // deallocator per module -- twelve of them -- and taking only the most popular
        // left the other eleven unrecognised, which made endsInDeallocator blind to whole
        // modules' worth of deleting destructors.
        //
        // The bar has to be relative, though. A flat floor of three agreeing pairs looked
        // safe and was not: across 2,600 tables, dozens of ordinary helpers are the single
        // extra call in three or four adjacent pairs by coincidence, and it accepted 91.
        // The real deallocators sit at the head of the distribution by a wide margin
        // (972, 161, 157, 117, ... against a tail of 3s), so a fraction of the winner
        // separates them where a constant cannot.
        int best = tally.values().stream().mapToInt(Integer::intValue).max().orElse(0);
        int floor = Math.max(MIN_OPERATOR_DELETE_AGREEMENT,
                best / OPERATOR_DELETE_TAIL_RATIO);
        List<Map.Entry<Address, Integer>> accepted = tally.entrySet().stream()
                .filter(e -> e.getValue() >= floor)
                .filter(e -> isDeallocatorCandidate(e.getKey()))
                .sorted((a, b) -> b.getValue() - a.getValue())
                .toList();
        if (accepted.isEmpty()) {
            script.printf("    No operator delete: best candidate agreed on by %d pairs\n",
                    best);
            return;
        }

        StringBuilder detail = new StringBuilder();
        for (Map.Entry<Address, Integer> entry : accepted) {
            Address addr = entry.getKey();
            operatorDeleteAddrs.add(addr.getOffset() & ~1L);
            if (!detail.isEmpty()) detail.append(", ");
            detail.append(addr).append(" (").append(entry.getValue()).append(")");
        }

        // One name, one address -- and this one especially. Every accepted candidate used
        // to get a _ZdlPv label, which put that symbol on sixteen addresses at once, only
        // one of which is ::operator delete. The rest are per-module and per-class
        // deallocators with no recoverable name: real functions, worth knowing about so a
        // D0's tail can be recognised, but not worth inventing a name for. Only the
        // best-agreed one is named, and only if nothing better is there already.
        Address primary = accepted.get(0).getKey();
        try {
            if (getNonGenericName(primary) == null) {
                symTab.createLabel(primary, "_ZdlPv", program.getGlobalNamespace(),
                        SourceType.ANALYSIS);
                detachThunksTo(primary);
            }
        } catch (Exception e) {
            script.println("WARNING: Could not label operator delete at " + primary);
        }
        script.printf("    Detected %d deallocator%s, each the extra call in that many "
                + "destructor pairs (only %s is named _ZdlPv): %s\n", accepted.size(),
                accepted.size() == 1 ? "" : "s", primary, detail);
        nameArrayDelete(primary);
    }

    /**
     * {@code operator delete[]}, found as the one function that is {@code operator
     * delete}'s twin.
     *
     * <p>sead defines both the same way, so their bodies are identical but for the branch
     * offsets -- which is exactly why nothing in the tally can separate them, and why the
     * two were being treated as interchangeable. The Rogue Wave library settles it:
     * {@code std::__rw_exception::D0} ends in {@code 0x2ffb64}, and a D0 calls
     * {@code operator delete}, while {@code __rw_exception::D2} calls {@code 0x2f88b8} on
     * its message buffer, which is {@code delete[] _C_what}.
     *
     * <p>So the scalar one is the one the destructor pairs agree on, and the array one is
     * its twin. Named only when the twin is unique: two would mean the shape is not the
     * discriminator it looks like.
     */
    private void nameArrayDelete(Address scalar) {
        byte[] want = branchBlindBody(scalar);
        if (want == null) return;

        Address found = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            Address at = f.getEntryPoint();
            if (at.equals(scalar)) continue;
            byte[] body = branchBlindBody(at);
            if (body == null || !Arrays.equals(want, body)) continue;
            if (found != null) return;                  // not unique; say nothing
            found = at;
        }
        if (found == null) return;
        try {
            if (getNonGenericName(found) == null) {
                symTab.createLabel(found, "_ZdaPv", program.getGlobalNamespace(),
                        SourceType.ANALYSIS);
                detachThunksTo(found);
                operatorDeleteAddrs.add(found.getOffset() & ~1L);
                script.printf("    operator delete[]:      _ZdaPv at %s, the one function " +
                        "whose body matches _ZdlPv apart from its branch offsets\n", found);
            }
        } catch (Exception e) {
            script.println("WARNING: Could not label _ZdaPv at " + found);
        }
    }

    /**
     * A function's bytes with every branch instruction's offset field blanked, so two
     * copies of the same source compiled into different places compare equal.
     */
    private byte[] branchBlindBody(Address entry) {
        Function f = program.getListing().getFunctionAt(entry);
        if (f == null) return null;
        long size = f.getBody().getNumAddresses();
        if (size < 8 || size > IDENTITY_BYTES || f.getBody().getNumAddressRanges() != 1) {
            return null;
        }
        byte[] bytes = new byte[(int) size];
        try {
            if (mem.getBytes(entry, bytes) != bytes.length) return null;
            InstructionIterator it = program.getListing().getInstructions(f.getBody(), true);
            while (it.hasNext()) {
                Instruction inst = it.next();
                FlowType flow = inst.getFlowType();
                if (!flow.isCall() && !flow.isJump()) continue;
                int off = (int) inst.getAddress().subtract(entry);
                for (int i = 0; i < inst.getLength() && off + i < bytes.length; i++) {
                    bytes[off + i] = 0;
                }
            }
        } catch (Exception e) {
            return null;
        }
        return bytes;
    }

    /** Longest function compared byte for byte when looking for a twin. */
    private static final int IDENTITY_BYTES = 256;

    /**
     * Whether an address can be a deallocator at all.
     *
     * <p>A deallocator is a free function. Nothing in a vtable is: a one-instruction
     * {@code B <deallocator>} sitting in a slot is that class's D0, not another
     * {@code operator delete}, and naming it one puts a free function's symbol on a virtual
     * method. That single test throws out ten of the sixteen addresses this pass had
     * accepted -- {@code nn::fs::IOutputStream}'s D0 and D1, {@code Base}'s slot 7 and
     * slot 5, several empty virtuals and one ordinary 504-byte method.
     *
     * <p>The rest of the test is that it has to be a function. One accepted address was not
     * code at all.
     */
    private boolean isDeallocatorCandidate(Address addr) {
        if (addr == null) return false;
        if (program.getListing().getFunctionAt(addr) == null) return false;
        if (pureVirtualChain.contains(addr.getOffset() & ~1L)) return false;
        return !allSlotTargets.contains(addr.getOffset() & ~1L);
    }

    /** {@code __cxa_pure_virtual} and what it calls: the pure-virtual trap, not deletion. */
    // Insertion-ordered: nameRuntimeChain walks it as a chain, so the order is the data.
    private final Set<Long> pureVirtualChain = new LinkedHashSet<>();

    /**
     * The ARM C++ library's pure-call chain is fixed, so once
     * {@code __cxa_pure_virtual} is known the two functions behind it are too:
     * {@code cpprt_5.l(pure_virt.o)} calls {@code __rt_SIGPVFN}
     * ({@code c_5.l(defsig_pvfn_formal.o)}), which calls {@code __rt_raise}. Named only
     * when the chain is the unbranching one the library emits, and never over a name
     * something better informed already put there.
     */
    private void nameRuntimeChain() {
        String[] chain = {null, "__rt_SIGPVFN", "__rt_raise"};
        List<Long> walk = new ArrayList<>(pureVirtualChain);
        int i = 0;
        for (Long off : walk) {
            if (i >= chain.length) break;
            String want = chain[i++];
            if (want == null) continue;
            Address at = toAddress(off);
            if (getNonGenericName(at) != null) continue;
            try {
                symTab.createLabel(at, want, program.getGlobalNamespace(),
                        SourceType.ANALYSIS);
                detachThunksTo(at);
                script.printf("    Runtime chain:          %s at %s, reached from " +
                        "__cxa_pure_virtual\n", want, at);
            } catch (Exception e) {
                // Already named; nothing to do.
            }
        }
    }

    /**
     * Walk out from {@code __cxa_pure_virtual} and remember what it reaches.
     *
     * <p>{@code 0x1024e0} was being accepted as a deallocator on 106 agreeing destructor
     * pairs, and it is the ARM library's {@code __rt_SIGPVFN} -- the handler
     * {@code __cxa_pure_virtual} calls to report a pure call, which in turn calls
     * {@code __rt_raise}. Every abstract class's vtable points at
     * {@code __cxa_pure_virtual}, so this chain sits at the end of a great many slot pairs
     * and looks exactly like the single extra call the tally is looking for. Nothing on it
     * frees anything.
     *
     * <p>Only followed while each step has exactly one call target of its own, which is
     * what this chain looks like and what stops the walk turning into a general reachability
     * sweep the moment it meets a real function.
     */
    private void collectPureVirtualChain() {
        pureVirtualChain.clear();
        if (pureVirtualAddr == 0) return;
        Address at = toAddress(pureVirtualAddr & ~1L);
        for (int hop = 0; hop < 4 && at != null; hop++) {
            if (!pureVirtualChain.add(at.getOffset() & ~1L)) break;
            List<Address> targets = callTargets(at);
            at = (targets.size() == 1) ? targets.get(0) : null;
        }
    }

    /** Every address any vtable slot in the image points at, thumb bit masked off. */
    private final Set<Long> allSlotTargets = new HashSet<>();

    private void collectSlotTargets() {
        allSlotTargets.clear();
        if (vtableScan == null) return;
        for (VtableScan.VtableGroup group : vtableScan.groups()) {
            for (VtableScan.SubTable sub : group.subs()) {
                for (long raw : sub.slots()) {
                    if (raw != 0) allSlotTargets.add(raw & ~1L);
                }
            }
        }
    }

    /** The function a slot points at, thumb bit masked off. Null for an empty slot. */
    private Address slotTarget(List<Long> slots, int index) {
        long funcPtr = slots.get(index);
        if (funcPtr == 0) return null;
        return program.getMinAddress().getAddressSpace().getAddress(funcPtr & ~1L);
    }

    /**
     * Code writing the vtable pointer of this class or any ancestor. A destructor
     * stores its own and then each base's as it unwinds, and the compiler drops the
     * ones nothing observes, so the survivor may be an ancestor's.
     */
    private Set<Address> collectVtableWriters(String className) {
        return collectVtableWriters(className, new HashSet<>());
    }

    private Set<Address> collectVtableWriters(String className, Set<String> visited) {
        Set<Address> cached = vtableWriterCache.get(className);
        if (cached != null) return cached;
        if (!visited.add(className)) return Set.of();

        Set<Address> writers = new HashSet<>(ownVtableWriters(className));
        List<String> parents = parentMap.get(className);
        if (parents != null) {
            for (String parent : parents) {
                writers.addAll(collectVtableWriters(parent, visited));
            }
        }
        vtableWriterCache.put(className, writers);
        return writers;
    }

    /**
     * Code referring to one of this class's own vtable address points, plus one hop
     * back for the ARM literal pool the pointer is loaded from.
     */
    private Set<Address> ownVtableWriters(String className) {
        ReferenceManager refMgr = program.getReferenceManager();
        Set<Address> writers = new HashSet<>();
        List<Address> points = allVtableAddressPoints.get(className);
        if (points == null) return writers;
        for (Address point : points) {
            if (point == null) continue;
            for (Reference r : refMgr.getReferencesTo(point)) {
                Address from = r.getFromAddress();
                if (!writers.add(from)) continue;
                for (Reference lit : refMgr.getReferencesTo(from)) {
                    writers.add(lit.getFromAddress());
                }
            }
        }
        return writers;
    }

    private boolean writesOwnVtable(Address funcAddr, Set<Address> writers) {
        if (writers.isEmpty()) return false;
        Function func = program.getListing().getFunctionAt(funcAddr);
        if (func != null) {
            for (Address writer : writers) {
                if (func.getBody().contains(writer)) return true;
            }
            // A body that covers real code is the truth about this function's extent,
            // and the writer is not in it. Scanning on would read whatever follows --
            // padding, or the next function's code if that code is not itself a
            // defined function -- and credit this function with someone else's store.
            if (!isDegenerateBody(func)) return false;
        }
        return scanForVtableWriter(funcAddr, writers);
    }

    /**
     * A body too small to be the whole function: the one-byte stub left by creating a
     * function on undisassembled bytes, or a body that stops at the entry point.
     */
    private static boolean isDegenerateBody(Function func) {
        return func.getBody().getNumAddresses() <= DEGENERATE_BODY_BYTES;
    }

    /**
     * A slot that calls a base class's own destructor. A destructor unwinds by running
     * each base's, so a slot function that calls the D1 of one of its ancestors is one
     * -- and bases are named before the classes that derive from them, so those names
     * are already in place by the time this runs.
     *
     * Restricted to ancestors on purpose. Any method at all may destroy a local or a
     * member, and matching those would name half the vtable; calling the destructor of
     * a class you inherit from is the specific thing only a destructor does.
     *
     * Reached only when the vtable-store rules found nothing, so it adds names rather
     * than overriding better evidence, and operator delete has already claimed D0 by
     * this point.
     */
    private boolean callsAncestorDestructor(Address funcAddr, String className) {
        Set<String> ancestors = ancestorsOf(className);
        if (ancestors.isEmpty()) return false;

        Listing listing = program.getListing();
        Address limit = null;
        try {
            FunctionIterator after = listing.getFunctions(funcAddr.add(1), true);
            if (after.hasNext()) limit = after.next().getEntryPoint();
        } catch (Exception e) {
            // end of the address space; the instruction cap bounds the walk instead
        }

        Instruction inst = listing.getInstructionAt(funcAddr);
        for (int seen = 0; inst != null && seen < MAX_BODY_SCAN; seen++) {
            Address addr = inst.getAddress();
            if (limit != null && addr.compareTo(limit) >= 0) break;

            for (Reference ref : inst.getReferencesFrom()) {
                Address target = ref.getToAddress();
                if (target == null) continue;
                for (Symbol sym : symTab.getSymbols(target)) {
                    if (!isCompleteDestructorName(sym.getName())) continue;
                    Namespace ns = sym.getParentNamespace();
                    if (ns != null && ancestors.contains(ns.getName(true))) return true;
                }
            }
            inst = listing.getInstructionAfter(addr);
        }
        return false;
    }

    /** A complete-object destructor name: D1, D1_<sub>, or the mangled spelling. */
    private static boolean isCompleteDestructorName(String name) {
        return name.equals("D1") || name.startsWith("D1_") || name.endsWith("D1Ev");
    }

    private Set<String> ancestorsOf(String className) {
        Set<String> cached = ancestorCache.get(className);
        if (cached != null) return cached;

        Set<String> ancestors = new HashSet<>();
        Deque<String> queue = new ArrayDeque<>();
        queue.add(className);
        while (!queue.isEmpty()) {
            List<String> parents = parentMap.get(queue.poll());
            if (parents == null) continue;
            for (String parent : parents) {
                if (ancestors.add(parent)) queue.add(parent);
            }
        }
        ancestorCache.put(className, ancestors);
        return ancestors;
    }

    /**
     * Body-independent form of the same question, for a function whose recorded body
     * is short of the truth. A function created before its bytes were disassembled
     * keeps a one-byte body (see FixFunctionBodies), which contains nothing but the
     * entry point, so the load of the vtable pointer falls outside it and a plain
     * destructor reads as an ordinary slot.
     *
     * Walks instructions from the entry to the next function entry. That bound is
     * loose -- code after the function belongs to a neighbour whether or not anything
     * declared it one -- so this runs only where the body is degenerate and there is
     * nothing better to go on.
     */
    private boolean scanForVtableWriter(Address funcAddr, Set<Address> writers) {
        Listing listing = program.getListing();
        Address limit = null;
        try {
            FunctionIterator after = listing.getFunctions(funcAddr.add(1), true);
            if (after.hasNext()) limit = after.next().getEntryPoint();
        } catch (Exception e) {
            // end of the address space; scan runs to the instruction cap instead
        }

        Instruction inst = listing.getInstructionAt(funcAddr);
        for (int seen = 0; inst != null && seen < MAX_BODY_SCAN; seen++) {
            Address addr = inst.getAddress();
            if (limit != null && addr.compareTo(limit) >= 0) break;
            if (writers.contains(addr)) {
                dtorByScan++;
                return true;
            }
            inst = listing.getInstructionAfter(addr);
        }
        return false;
    }

    /**
     * D0/D1 if this slot holds a thunk to a function already named that. Targets are
     * named first, since a class's primary sub-vtable is processed before its
     * secondaries.
     */
    private String thunkedDestructorKind(Address funcAddr) {
        // Only the target's name counts, never this function's own: treating a name
        // this script wrote as evidence would make the first guess permanent.
        Function func = program.getListing().getFunctionAt(funcAddr);
        if (func == null || !isThunkSized(func)) return null;
        try {
            // By reference, not flow type: an adjustor thunk's branch carries a
            // CALL_RETURN override, so getFlowType() is not dependable here.
            InstructionIterator iter =
                    program.getListing().getInstructions(func.getBody(), true);
            while (iter.hasNext()) {
                Instruction inst = iter.next();
                for (Reference ref : inst.getReferencesFrom()) {
                    Address target = ref.getToAddress();
                    if (target == null || func.getBody().contains(target)) continue;
                    String kind = destructorKindAt(target);
                    if (kind != null) return kind;
                }
            }
        } catch (Exception e) {
            // fall through
        }
        return null;
    }

    /**
     * The function at this address, disassembling and creating one if need be.
     *
     * Disassembly comes first and in the right instruction set: CreateFunctionCmd
     * derives the body by following flow, so on undisassembled bytes it produces a
     * one-byte body that later disassembly never grows, and on bytes decoded as ARM
     * when they are really Thumb it follows nonsense. The pointer that led here
     * carries the Thumb bit, so pass it rather than leaving the mode to whatever the
     * context register happens to hold.
     */
    private Function ensureFunction(Address funcAddr, boolean thumb) {
        Function func = program.getListing().getFunctionAt(funcAddr);
        if (func != null) {
            if (func.getParentNamespace().getName().startsWith("switchD_")) {
                dropCaseLabels(funcAddr);
            }
            return func;
        }
        try {
            // Decoded in the other instruction set than the pointer says: the pointer is the
            // linker's record of how this address is entered, so it wins. Downtown 0xcddc is
            // reached by an even (ARM) pointer but had been decoded as Thumb "ands r0,r2",
            // and a function could not be made there. Only outside every function body, so
            // nothing already established is redecoded.
            // Out of any host first: the mode check below only redecodes outside bodies.
            endHostBefore(funcAddr);
            Instruction existing = program.getListing().getInstructionAt(funcAddr);
            if (existing != null && program.getFunctionManager().getFunctionContaining(funcAddr) == null
                    && isThumbAt(funcAddr) != thumb) {
                // The whole wrong-mode run, or the next wrong-mode instruction blocks the
                // redecode two bytes on.
                Address end = existing.getMaxAddress();
                for (int n = 0; n < 128; n++) {
                    Instruction next = program.getListing().getInstructionAt(end.next());
                    if (next == null || isThumbAt(next.getAddress()) == thumb
                            || program.getFunctionManager()
                                    .getFunctionContaining(next.getAddress()) != null) {
                        break;
                    }
                    end = next.getMaxAddress();
                }
                program.getListing().clearCodeUnits(funcAddr, end, false);
                modeRedecoded++;
            }
            if (program.getListing().getInstructionAt(funcAddr) == null) {
                // Defined data over the bytes makes the disassembler refuse outright, and
                // a vtable slot target is code whatever Ghidra decided earlier: the table
                // says so. That is 0x3b921c, a two-instruction "bx lr" destructor left as
                // data, which is how its class's slots ended up named after the DAT_ label
                // sitting on them. Only inside an executable block -- clearing data in
                // .constdata would take a vtable apart.
                Data data = program.getListing().getDataContaining(funcAddr);
                MemoryBlock block = mem.getBlock(funcAddr);
                if (data != null && data.isDefined()
                        && block != null && block.isExecute()) {
                    program.getListing().clearCodeUnits(
                            data.getMinAddress(), data.getMaxAddress(), false);
                }
                new ArmDisassembleCommand(funcAddr, null, thumb).applyTo(program);
            }
            endHostBefore(funcAddr);
            CreateFunctionCmd fCmd = new CreateFunctionCmd(funcAddr);
            fCmd.applyTo(program);
            func = program.getListing().getFunctionAt(funcAddr);
            if (func != null) dropCaseLabels(funcAddr);
        } catch (Exception e) {
            script.println("WARNING: Could not create function at " + funcAddr);
        }
        return func;
    }

    private int modeRedecoded = 0;
    private int pureDestructors = 0;

    /**
     * A pure virtual destructor: slots 0/1 of the class's primary table both hold
     * __cxa_pure_virtual, and a direct derived class has a real destructor pair at 0/1 --
     * D0 being D1 plus one call. Then there is no D1/D0 in this table, and searching the rest
     * of it only finds destructor-shaped ordinary virtuals: script::Insert got D1/D0 on an
     * accessor and a forwarding branch at 187/188 (differently from run to run), and
     * script::ChoiceStandard a D1 at 7. Pure slots alone prove nothing -- ssys::ma::VramHeap
     * declares four pure virtuals before a real destructor at 9/10, as VramExpHeap's 9/10
     * confirm -- hence the derived-class evidence.
     */
    private boolean hasPureVirtualDestructor(String className, List<Long> slots) {
        if (slots.size() < 2 || !isPureSlot(slots.get(0)) || !isPureSlot(slots.get(1))) {
            return false;
        }
        for (String child : childrenMap.getOrDefault(className, List.of())) {
            List<String> ps = parentMap.get(child);
            if (ps == null || ps.isEmpty() || !className.equals(ps.getFirst())) continue;
            List<Long> cs = vtableSlots.get(child);
            if (cs == null || cs.size() < 2 || isPureSlot(cs.get(0)) || isPureSlot(cs.get(1))) {
                continue;
            }
            Address d1 = slotTarget(cs, 0);
            Address d0 = slotTarget(cs, 1);
            if (d1 != null && d0 != null && extraCall(d1, d0) != null) return true;
        }
        return false;
    }

    private boolean isPureSlot(Long raw) {
        return raw != null && raw != 0 && pureVirtualAddr != 0
                && (raw & ~1L) == (pureVirtualAddr & ~1L);
    }

    /** Whether the address is currently decoded as Thumb (TMode 1). */
    private boolean isThumbAt(Address a) {
        Register tmode = program.getLanguage().getRegister("TMode");
        if (tmode == null) return false;
        RegisterValue rv = program.getProgramContext().getRegisterValue(tmode, a);
        return rv != null && rv.hasValue() && rv.getUnsignedValue().intValue() == 1;
    }

    private int hostsEnded = 0;
    private final List<String> hostsEndedExamples = new ArrayList<>();

    /**
     * End the function whose body has run across a known entry point.
     *
     * <p>Every caller hands this an address the image itself says is an entry: a vtable
     * slot, an export, a veneer, a PLT entry. armcc emits each function as one contiguous
     * run with no hot/cold splitting, so a body that contains someone else's entry has
     * followed a fall-through that is not there -- usually --tailreorder adjacency, where
     * the previous function's tail call became a fall-through into this one. Three
     * sead::DualScreen* slots were the visible case: 0x54c0d0 sat inside the body as
     * "switchD_0054c064::default", so CreateFunctionCmd refused and the slot was never a
     * function. Everything from the entry to the host's end goes; the host keeps the rest.
     */
    private void endHostBefore(Address entry) {
        Function host = program.getListing().getFunctionContaining(entry);
        if (host == null || host.getEntryPoint().equals(entry)) return;
        try {
            // From the entry to the end of the body range holding it -- not to the host's
            // highest address. A tail branch to a PLT entry pulls the stub in as a separate
            // range *below* the host (the PLT sits at the start of .text), so "entry to max"
            // was an empty set there, nothing was cut, and 638 CRO PLT entries reaching a
            // code.bin D1 could never become functions or reach the export.
            AddressRange holding = host.getBody().getRangeContaining(entry);
            if (holding == null) return;
            AddressSet cut = new AddressSet(entry, holding.getMaxAddress());
            AddressSetView kept = host.getBody().subtract(cut);
            if (kept.isEmpty() || !kept.contains(host.getEntryPoint())) return;
            host.setBody(kept);
            hostsEnded++;
            if (hostsEndedExamples.size() < 8) {
                hostsEndedExamples.add(host.getName(true) + "@" + host.getEntryPoint()
                        + " ended before " + entry);
            }
        } catch (Exception e) {
            script.printf("    WARNING: could not end %s before the entry at %s: %s\n",
                    host.getName(), entry, e.getMessage());
        }
    }

    /**
     * Ghidra's switch-case labels on what is now a function entry: {@code switchD_…::default},
     * {@code caseD_…}. They were right about the jump table's shape, not about whose code it
     * reached, and they would otherwise sit beside the function's name.
     */
    private void dropCaseLabels(Address entry) {
        Function f = program.getListing().getFunctionAt(entry);
        for (Symbol s : symTab.getSymbols(entry)) {
            String ns = s.getParentNamespace().getName();
            if (!(ns.startsWith("switchD_") || s.getName().startsWith("caseD_"))) continue;
            try {
                // CreateFunctionCmd adopts the label already on the address as the
                // function's name, so 0x54416c came out as a function called "default" in
                // namespace switchD_00544134 -- and a non-placeholder name there made the
                // slot naming leave it alone. The function symbol cannot be deleted, only
                // given back its default name.
                if (f != null && s.equals(f.getSymbol())) {
                    f.setParentNamespace(program.getGlobalNamespace());
                    f.setName(null, SourceType.DEFAULT);
                } else {
                    s.delete();
                }
            } catch (Exception e) {
                // leave it
            }
        }
    }

    /** Small enough to be an adjustor stub rather than a function of its own. */
    private boolean isThunkSized(Function func) {
        return func.getBody().getNumAddresses() <= THUNK_MAX_BYTES;
    }

    /**
     * Delete function-shaped mangled names this pass left at addresses no vtable reaches.
     *
     * <p>Every other cleanup in this pass is driven by walking the tables, so it can only
     * revise addresses the walk still visits. A name written by an earlier run at an
     * address that is no longer a slot target -- because the slot walk was shortened, or
     * because the run propagated a name to a branch target it should not have -- is never
     * looked at again and simply persists.
     *
     * <p>That is how {@code _ZN4sead10AudioFxCtrD1Ev} came to be at two addresses: the
     * real 60-byte destructor at {@code 0x14152c}, which is in the vtable, and a 4-byte
     * branch stub at {@code 0x1433c8}, which is in nothing. The duplicate guard in
     * {@link #emitMangledNames} cannot see the second one, because planning only covers
     * slot targets. One name at two addresses is something armcc never emits, so the one
     * with no table behind it goes.
     *
     * <p>Deliberately narrow. Only {@code SourceType.ANALYSIS} symbols -- this pass's own
     * output, never an imported or hand-written name -- and only the function forms
     * {@code _ZN}, {@code _ZTh} and {@code _ZTv}. The data forms ({@code _ZTV},
     * {@code _ZTI}, {@code _ZTS}, {@code _ZTT}, {@code _ZT_C1_}) live at addresses that
     * are not slot targets by definition and must not be swept up.
     */
    private void pruneStaleMangledNames() {
        if (vtableScan == null) return;

        Set<Long> legitimate = new HashSet<>();
        for (VtableScan.VtableGroup group : vtableScan.groups()) {
            for (VtableScan.SubTable sub : group.subs()) {
                for (long raw : sub.slots()) {
                    if (raw != 0) legitimate.add(raw & ~1L);
                }
            }
        }
        legitimate.addAll(mangledAliasAddrs);

        int pruned = 0;
        for (Symbol sym : symTab.getAllSymbols(false)) {
            if (sym.getSource() != SourceType.ANALYSIS) continue;
            String name = sym.getName();
            if (!name.startsWith("_ZN") && !name.startsWith("_ZTh")
                    && !name.startsWith("_ZTv")) continue;
            if (legitimate.contains(sym.getAddress().getOffset())) continue;
            sym.delete();
            pruned++;
        }
        if (pruned > 0) {
            script.printf("    Stale names pruned:     %d mangled names at addresses no " +
                    "vtable slot points to\n", pruned);
        }
    }

    /** Addresses this run deliberately gave a mangled name that is not a slot target. */
    private final Set<Long> mangledAliasAddrs = new HashSet<>();

    /**
     * Give armlink's veneers the names armlink gives them.
     *
     * <p>A veneer is a hop the linker inserts to reach a target its caller's branch could
     * not encode, or to switch instruction set on the way. It belongs to no class and
     * implements nothing, so leaving 285 of them as {@code FUN_*} mixed in with real
     * functions invites exactly the mistake {@code thunkAdjustment} already guards
     * against -- reading an immediate out of one and calling it a this-adjustment.
     *
     * <p>Each form is matched on its exact encoding, so a match is proof rather than a
     * guess; nothing is renamed on size or shape alone. The three armlink emits here:
     *
     * <pre>
     *   e51ff004  LDR pc,[pc,#-4]   + DCD target    $Ven$AA$L$$&lt;target&gt;
     *   e28fc0NN  ADD r12,pc,#NN
     *   e12fff1c  BX  r12                           $Ven$AT$I$$&lt;target&gt;  (NN = 1 + the
     *                                               target's offset in its Thumb section)
     *   4778 46c0 BX pc ; NOP            (Thumb)    $Ven$TA$I$$&lt;target&gt;
     * </pre>
     *
     * <p>The interworking forms carry no pointer: the ARM-to-Thumb one encodes the target
     * in its ADR immediate, and the Thumb-to-ARM one falls straight through to the
     * function that follows it. The armlink spelling embeds the target's name; a target
     * with no recovered name yet lends its current one, revised on the next run.
     */
    /** Stubs that must share a literal before it is read as the unresolved-import handler. */
    private static final int PLT_SHARED_LITERAL_MIN = 8;

    /** The CRO loader's unresolved-import handler, or null. Never a method of any class. */
    private Address unresolvedImportHandler;
    private int pltEntriesNamed = 0;
    private int pltEntriesUnnamed = 0;
    private int pltEntriesAnonymous = 0;
    /** Veneers whose encoding matched but whose target carries no name to embed. */
    private int veneerTargetUnnamed = 0;

    /**
     * Tell armlink's BPABI import stubs apart from its veneers, which share their bytes.
     *
     * <p>A {@code --bpabi} executable calling into a {@code --bpabi --dll} gets one 8-byte
     * {@code .plt} entry per imported symbol -- {@code LDR pc,[pc,#-4]} and a literal, the
     * same encoding as the long-form veneer -- and every call site goes through it whether
     * or not the target is in range. armlink writes 0 in the literal and leaves a dynamic
     * relocation; ACNL's CRO loader pre-fills it with the module's unresolved-import
     * handler instead, and the real target lives in the import record.
     *
     * <p>So the literal in an import stub names neither the target nor anything else. ACNL
     * has 604 of these in one run at {@code 0x14f6fc}, and reading their literals as veneer
     * targets put {@code $Ven$AA$L$$} plus one CRO class's method name on 192 of them --
     * a name that is wrong twice over, since they are not veneers and the handler is not
     * that class's method.
     *
     * <p>Two things separate them, and this collects both before naming anything: the
     * handler is the one literal value that dozens of stubs share (a veneer's literal is
     * its own target, so it is shared by a handful at most), and {@code CRXLibrary} has
     * already put an external reference on the stub naming the exporting module.
     */
    /**
     * An 8-byte long-form stub inside the PLT.
     *
     * <p>Decided per entry in {@link #surveyImportStubs}: the literal <em>as the file has
     * it</em> is the unresolved-import handler, or the word carries an import record. The
     * earlier per-entry test read relocated memory and so missed 405 of 604; the "longest
     * run" rule that replaced it would miss a second PLT, which armlink makes per load
     * region under scatter-loading. Reading the file bytes fixes the first without the
     * second.
     */
    private boolean isImportStub(Address entry) {
        return pltEntries.contains(entry.getOffset());
    }

    /** Every PLT entry, from every PLT the image has. */
    private final Set<Long> pltEntries = new HashSet<>();

    private void surveyImportStubs() {
        unresolvedImportHandler = null;
        pltEntries.clear();
        // Over memory, not over the function list. Ghidra has a function on only a
        // fraction of these -- nothing calls most of them from code it has disassembled --
        // so walking functions found 23 of 604 and the run collapsed to the longest
        // stretch that happened to have functions on it. The PLT is a property of the
        // bytes, so the bytes are what gets read.
        // The literal as the file has it, not as memory has it. Every one of ACNL's 604 is
        // the handler on disk; memory shows other values only because CRXLibrary applied
        // the CRO import relocations over them, which is why the in-memory tally found the
        // handler shared by just 192 (open answers 2, Q15).
        Map<Long, Integer> literalTally = new HashMap<>();
        Map<Long, Long> rawLiteral = new HashMap<>();
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || !block.isExecute()) continue;
            long start = block.getStart().getOffset();
            long end = block.getEnd().getOffset();
            for (long off = (start + 3) & ~3L; off + 8 <= end; off += PTR_SIZE) {
                try {
                    Address at = toAddress(off);
                    if (mem.getInt(at) != 0xe51ff004) continue;
                    long literal = rawWord(at.add(4));
                    rawLiteral.put(off, literal);
                    if (literal != 0 && (literal & 1L) == 0) {
                        literalTally.merge(literal, 1, Integer::sum);
                    }
                } catch (Exception e) {
                    // Unreadable word; keep going.
                }
            }
        }
        int bestCount = 0;
        for (Map.Entry<Long, Integer> e : literalTally.entrySet()) {
            if (e.getValue() > bestCount) {
                bestCount = e.getValue();
                unresolvedImportHandler = toAddress(e.getKey());
            }
        }
        if (bestCount < PLT_SHARED_LITERAL_MIN) unresolvedImportHandler = null;

        // Each entry on its own merits, not "the longest run": armlink makes one PLT per
        // load region under --base_platform --pltgot=direct with a scatter file (Q14), and
        // a second run would have been misnamed as veneers. An entry is one whose file
        // literal is the handler, or which carries a CRO import record -- the second test
        // is what still works for an image whose literals were bound before it was dumped.
        long handler = (unresolvedImportHandler == null) ? -1 : unresolvedImportHandler.getOffset();
        for (Map.Entry<Long, Long> e : rawLiteral.entrySet()) {
            Address at = toAddress(e.getKey());
            if (e.getValue() == handler || hasImportRecord(at) || hasImportRecord(at.add(4))
                    || literalNeverFilled(at, e.getValue())) {
                pltEntries.add(e.getKey());
            }
        }
        if (unresolvedImportHandler == null) return;

        // The handler loads a string and branches on to a bare "bx lr". That second
        // address is just as much not-a-method as the first, and carried the same invented
        // name, so both are taken out of circulation together.
        unresolvedImportTail = tailBranchTarget(unresolvedImportHandler);
        if (unresolvedImportTail == null) {
            unresolvedImportTail = firstBranchFrom(unresolvedImportHandler);
        }
        script.printf("    Unresolved imports:     handler %s, its tail %s\n",
                unresolvedImportHandler, unresolvedImportTail);
        nameNeutral(unresolvedImportHandler, HANDLER_NAME);
        clearToDefault(unresolvedImportTail);
    }

    /**
     * Take every name this pipeline or a propagation put on an address that should have none,
     * leaving Ghidra's default. The handler's tail is shared code nothing in the files names,
     * so any name on it -- a loader name, an old placeholder, a class method copied along a
     * slot -- is wrong. A global name somebody else chose (imported, hand-written, not ours)
     * stays.
     */
    private void clearToDefault(Address addr) {
        if (addr == null) return;
        Function f = program.getListing().getFunctionAt(addr);
        try {
            if (f != null && f.isThunk()) f.setThunkedFunction(null);
            detachThunksTo(addr);
        } catch (Exception e) {
            // Leave the thunk; the names below still go.
        }
        for (Symbol s : symTab.getSymbols(addr)) {
            if (s.getSource() == SourceType.DEFAULT) continue;
            String n = s.getName();
            boolean ours = LOADER_ENTRY_NAMES.contains(n) || RETIRED_HANDLER_NAMES.contains(n)
                    || n.startsWith("_Z") || !s.getParentNamespace().isGlobal();
            if (!ours) continue;
            try {
                if (f != null && s.equals(f.getSymbol())) {
                    f.setName(null, SourceType.DEFAULT);
                } else {
                    s.delete();
                }
            } catch (Exception e) {
                script.printf("    WARNING: could not clear %s at %s: %s\n", n, addr,
                        e.getMessage());
            }
        }
    }

    /**
     * An {@code LDR pc,[pc,#-4]} whose literal is zero in the file and still zero in memory:
     * a jump to address 0, which no veneer is. In a CRO every pointer ships as zero, and the
     * loader fills a veneer's literal from the module's own relocations; an import's literal
     * it leaves for the import to bind. So a literal nothing ever filled is an import stub,
     * whether or not its import record survived -- and in ModuleMusFish half of them had
     * not, which is how stubs identical to their neighbours came out as
     * {@code $Ven$AA$L$$FUN_00000000}. code.bin's literals all hold the handler, so this
     * never fires there.
     */
    private boolean literalNeverFilled(Address entry, long rawLiteral) {
        if (rawLiteral != 0) return false;
        try {
            return mem.getInt(entry.add(4)) == 0;
        } catch (MemoryAccessException e) {
            return false;
        }
    }

    /** True when CRXLibrary left an import record on this word. */
    private boolean hasImportRecord(Address at) {
        for (Reference ref : program.getReferenceManager().getReferencesFrom(at)) {
            if (ref instanceof ExternalReference) return true;
        }
        return false;
    }

    /**
     * A word as the loaded file has it, before any relocation Ghidra or a script applied
     * on top. Falls back to memory when the block has no file bytes behind it.
     */
    private long rawWord(Address at) throws MemoryAccessException {
        MemoryBlock block = mem.getBlock(at);
        if (block != null) {
            for (MemoryBlockSourceInfo info : block.getSourceInfos()) {
                if (!info.contains(at) || info.getFileBytes().isEmpty()) continue;
                FileBytes fb = info.getFileBytes().get();
                long off = info.getFileBytesOffset(at);
                if (off < 0) continue;
                try {
                    long v = 0;
                    for (int i = 3; i >= 0; i--) {
                        v = (v << 8) | (fb.getOriginalByte(off + i) & 0xffL);
                    }
                    return v;
                } catch (IOException e) {
                    break;
                }
            }
        }
        return Integer.toUnsignedLong(mem.getInt(at));
    }

    /** The instruction word at {@code at} as the file has it, as a signed int. */
    private int rawInt(Address at) throws MemoryAccessException {
        return (int) rawWord(at);
    }

    /** The halfword at {@code at} as the file has it. */
    private int rawShort(Address at) throws MemoryAccessException {
        long aligned = at.getOffset() & ~3L;
        long w = rawWord(toAddress(aligned));
        return (int) ((at.getOffset() & 2L) == 0 ? (w & 0xffff) : ((w >>> 16) & 0xffff));
    }

    /**
     * The target of the first unconditional branch in the few instructions from
     * {@code start}, read off the listing rather than a function body. ACNL's handler is
     * {@code ADD r0,pc,#0 ; B 0x16d7f4}; when Ghidra's function there is not the plain
     * two-instruction body tailBranchTarget expects, the tail went unnamed and kept
     * showing the handler's name through Ghidra's thunk.
     */
    private Address firstBranchFrom(Address start) {
        if (start == null) return null;
        Instruction inst = program.getListing().getInstructionAt(start);
        for (int i = 0; inst != null && i < 4; i++) {
            if (inst.getFlowType().isJump() && !inst.getFlowType().isConditional()) {
                Address[] flows = inst.getFlows();
                return (flows.length == 1) ? flows[0] : null;
            }
            inst = inst.getNext();
        }
        return null;
    }

    /** Where the handler hands off, or null. */
    private Address unresolvedImportTail;

    /** The address a function's last instruction branches to, outside its own body. */
    private Address tailBranchTarget(Address funcAddr) {
        try {
            Function func = program.getListing().getFunctionAt(funcAddr);
            if (func == null) return null;
            InstructionIterator back =
                    program.getListing().getInstructions(func.getBody(), false);
            if (!back.hasNext()) return null;
            Instruction last = back.next();
            if (!last.getFlowType().isJump()) return null;
            for (Reference ref : last.getReferencesFrom()) {
                Address target = ref.getToAddress();
                if (target != null && !func.getBody().contains(target)) return target;
            }
        } catch (Exception e) {
            // Nothing readable here.
        }
        return null;
    }

    /**
     * Clear a runtime address of any name that claims a class, and say what it is instead.
     *
     * <p>Every mangled spelling goes, whoever wrote it. That is the one place this pass
     * deletes an imported or hand-written name rather than reporting it, and the reason is
     * that the address is decided structurally: hundreds of import stubs point here, which
     * no method of any class could be the target of.
     */
    private void nameNeutral(Address addr, String neutral) {
        if (addr == null) return;
        Function func = program.getListing().getFunctionAt(addr);
        // A Ghidra thunk has no name of its own -- it shows its target's, which is how the
        // handler's "bx lr" tail came out as cro_unresolved_import_handler_0016d7f4. The
        // loop below skips global names, so it would never have touched this one.
        if (func != null && func.isThunk()) {
            try {
                renameEntryNeutral(func, neutral);
            } catch (Exception e) {
                script.printf("    WARNING: could not un-thunk %s: %s\n", addr, e.getMessage());
            }
        }
        Symbol entrySym = (func == null) ? null : func.getSymbol();

        for (Symbol sym : symTab.getSymbols(addr)) {
            String name = sym.getName();
            if (sym.getSource() == SourceType.DEFAULT) continue;
            if (name.equals(neutral)) continue;
            // A global name is left alone -- except a loader name that is not this
            // address's own: OnUnresolved propagated onto the tail, say, or OnLoad/OnExit
            // wherever they strayed.
            if (!name.startsWith("_Z") && sym.getParentNamespace().isGlobal()
                    && !LOADER_ENTRY_NAMES.contains(name)
                    && !RETIRED_HANDLER_NAMES.contains(name)) continue;
            script.printf("    Dropping %s at %s: it is CRO loader code, not a method\n",
                    name, addr);
            try {
                // A function's entry symbol cannot be deleted -- delete() takes the
                // function with it, or quietly does nothing and leaves the name primary,
                // which is why the old name kept coming out of the export. Rename it
                // instead, which is the same outcome for a symbol that carries no
                // information worth keeping.
                if (sym.equals(entrySym)) {
                    renameEntryNeutral(func, neutral);
                } else if (!sym.delete()) {
                    script.printf("    WARNING: could not delete %s at %s\n", name, addr);
                }
            } catch (Exception e) {
                script.printf("    WARNING: could not clear %s at %s: %s: %s\n", name, addr,
                        e.getClass().getSimpleName(), e.getMessage());
            }
        }
        try {
            Symbol made = symTab.createLabel(addr, neutral, program.getGlobalNamespace(),
                    SourceType.ANALYSIS);
            detachThunksTo(addr);
            if (made != null && entrySym == null) made.setPrimary();
        } catch (Exception e) {
            // Already there.
        }
    }

    /**
     * Take the CRO header's entry-point names off every function that carries one inside a
     * class.
     *
     * <p>{@code OnLoad}/{@code OnExit}/{@code OnUnresolved} are what CRXLibrary calls the
     * addresses a module's header lists, always in the global namespace. Found in a class,
     * the name was propagated there from a CRO slot that reads as its module's handler
     * until the import is bound -- that is how {@code DemoActor}, {@code script::IRecept}
     * and {@code 0x16d7f4} ended up with an {@code OnUnresolved} method. Propagation writes
     * {@code USER_DEFINED}, so the source cannot tell these apart from a hand-typed name;
     * the name can, because no method is called that by the loader's convention. The
     * function goes back to its default name.
     */
    private void clearLoaderNamesOnMethods() {
        int cleared = 0;
        List<Symbol> hits = new ArrayList<>();
        SymbolIterator it = symTab.getAllSymbols(false);
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.getParentNamespace().isGlobal()) continue;
            String n = s.getName();
            boolean loader = n.equals("OnLoad") || n.equals("OnExit") || n.equals("OnUnresolved")
                    || n.startsWith("OnUnresolved_") || n.startsWith("OnLoad_")
                    || n.startsWith("OnExit_");
            if (loader) hits.add(s);
        }
        it = symTab.getAllSymbols(false);
        while (it.hasNext()) {
            Symbol s = it.next();
            String n = s.getName();
            if (n.startsWith("_Z") && (n.endsWith("12OnUnresolvedEv") || n.endsWith("6OnLoadEv")
                    || n.endsWith("6OnExitEv"))) {
                hits.add(s);
            }
        }
        for (Symbol s : hits) {
            Address at = s.getAddress();
            try {
                Function f = program.getListing().getFunctionAt(at);
                if (f != null && s.equals(f.getSymbol())) {
                    if (f.isThunk()) f.setThunkedFunction(null);
                    if (at.equals(unresolvedImportHandler) || at.equals(unresolvedImportTail)) {
                        continue;   // nameNeutral has already given it its name
                    }
                    f.setParentNamespace(program.getGlobalNamespace());
                    try {
                        f.setName(null, SourceType.DEFAULT);
                    } catch (Exception e) {
                        // The spelling Ghidra's default would have; generic to every
                        // reader here, so the slot is named afresh like any other.
                        f.setName(String.format("FUN_%08x", at.getOffset()),
                                SourceType.ANALYSIS);
                    }
                } else {
                    s.delete();
                }
                cleared++;
            } catch (Exception e) {
                script.printf("    WARNING: could not clear %s at %s: %s\n",
                        s.getName(true), at, e.getMessage());
            }
        }
        if (cleared > 0) {
            script.printf("    Loader names:           %d CRO entry-point names taken off "
                    + "methods they had spread to\n", cleared);
        }
    }

    /**
     * Move a function's own name to the neutral one in the global namespace.
     *
     * <p>Three things have each stopped the one-step rename on its own: a label of the
     * neutral name already at the address (an earlier call in this run, or an earlier run,
     * made it -- the rename then collides with it), the function being a Ghidra thunk,
     * whose name is its target's and cannot be set, and a namespace move refused on its
     * own. So clear the way first and fall back to doing the two halves separately.
     */
    private void renameEntryNeutral(Function func, String neutral) throws Exception {
        Namespace global = program.getGlobalNamespace();
        if (func.isThunk()) func.setThunkedFunction(null);
        Symbol entry = func.getSymbol();
        for (Symbol other : symTab.getSymbols(func.getEntryPoint())) {
            if (!other.equals(entry) && other.getName().equals(neutral)) other.delete();
        }
        try {
            entry.setNameAndNamespace(neutral, global, SourceType.ANALYSIS);
        } catch (Exception first) {
            func.setParentNamespace(global);
            func.setName(neutral, SourceType.ANALYSIS);
        }
    }

    /**
     * The import record behind a stub, as {@code <symbol>@<module>}.
     *
     * <p>{@code CRXLibrary.applyRelocs} puts an external reference on the patched word when
     * it links the modules, so the exporting module and the symbol it exports are already
     * recorded. Where the symbol is only known as a module offset, the armlink map file's
     * spelling has nothing to offer either, so the name says plainly what it is.
     */
    private String importStubName(Address entry) {
        return pltName(program, entry, this::openCroProgram);
    }

    /**
     * armlink's map-file name for a PLT entry, {@code <target>@<soname>}, from the entry's
     * import record; null when the entry has none.
     *
     * <p>The soname is the import-module string verbatim: armlink stores
     * {@code --soname=|static|} as given, and the map then shows {@code _ZdlPv@|static|}
     * (output fixes, "CRO imports"; q18_plt_mapname.py). The target part is whatever the
     * target module currently calls the function -- a {@code _Z} name where there is one,
     * else its function name, {@code FUN_…} included -- with the Thumb bit cleared. An
     * honest {@code FUN_00306978@|static|} says exactly what is known and where to look;
     * the neutral {@code plt_} form this replaces said less. Names are only as good as the
     * target module's at the time, which is why CROLink calls {@link #renamePltEntries}
     * again once every module has been through the pipeline.
     */
    public static String pltName(Program p, Address entry,
                                 java.util.function.Function<String, Program> openByPath) {
        for (Address at : new Address[]{entry, entry.add(4)}) {
            for (Reference ref : p.getReferenceManager().getReferencesFrom(at)) {
                if (!(ref instanceof ExternalReference extRef)) continue;
                ExternalLocation loc = extRef.getExternalLocation();
                String module = loc.getLibraryName();
                Address ta = loc.getAddress();
                String target = null;
                Library lib = p.getExternalManager().getExternalLibrary(module);
                if (lib != null && lib.getAssociatedProgramPath() != null && ta != null) {
                    Program tp = openByPath.apply(lib.getAssociatedProgramPath());
                    if (tp != null) target = currentName(tp, ta.getOffset() & ~1L);
                }
                if (target == null && ta != null) {
                    target = String.format("FUN_%08x", ta.getOffset() & ~1L);
                }
                if (target == null) {
                    String label = loc.getLabel();
                    if (label == null || label.isBlank()) return null;
                    target = label;
                }
                return target + "@" + module;
            }
        }
        return null;
    }

    /** What a module calls the function at this offset now: a {@code _Z} name if any. */
    private static String currentName(Program tp, long offset) {
        Address a = tp.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        // Of an alias pair, the C1/D1 spelling: armcc references the complete-object
        // structor even for a base subobject (q21_dtor_callee.py), so that is the symbol
        // the import names, whichever of the two code.bin shows as primary.
        String mangled = null;
        for (Symbol s : tp.getSymbolTable().getSymbols(a)) {
            if (s.getSource() == SourceType.DEFAULT || !s.getName().startsWith("_Z")) continue;
            if (s.getName().matches("_Z.*[CD]1E.*")) return s.getName();
            if (mangled == null) mangled = s.getName();
        }
        if (mangled != null) return mangled;
        Function f = tp.getFunctionManager().getFunctionAt(a);
        // A Ghidra thunk shows the name of what it forwards to, so ten different targets
        // all read "thunk_FUN_0020ad0c" and the export told them apart with an address
        // tacked on after the soname. The thunk is its own function at its own address.
        if (f != null && f.isThunk() && f.getSymbol().getSource() == SourceType.DEFAULT) {
            return String.format("FUN_%08x", offset);
        }
        if (f != null) return f.getName(true);
        Symbol prim = tp.getSymbolTable().getPrimarySymbol(a);
        return (prim == null) ? null : prim.getName(true);
    }

    /**
     * Put {@code name} on the PLT entry's function, or give it back its default name when
     * {@code name} is null. Clears any {@code plt_} or {@code …@…} label an earlier run left.
     */
    private static boolean applyPltName(Program p, Address entry, String name) throws Exception {
        SymbolTable st = p.getSymbolTable();
        Function f = p.getFunctionManager().getFunctionAt(entry);
        // A PLT entry carries its import's name and nothing else: armlink writes no symbol
        // there, so any other analysis or propagated name (a class method, a destructor
        // alias) is one some pass copied onto the stub.
        for (Symbol s : st.getSymbols(entry)) {
            if (f != null && s.equals(f.getSymbol())) continue;
            if (s.getSource() == SourceType.IMPORTED || s.getSource() == SourceType.DEFAULT) continue;
            s.delete();
        }
        if (f == null) {
            // Every PLT entry is a function: 8 bytes, one "ldr pc" and its literal. Some were
            // never even disassembled -- nothing decoded reaches them -- so the label that used
            // to go here named an address with no function and no row (Kappei 0x5c8, and 29
            // more that looked like entries without an import record).
            if (p.getListing().getInstructionAt(entry) == null) {
                p.getListing().clearCodeUnits(entry, entry.add(3), false);
                new ArmDisassembleCommand(new AddressSet(entry, entry.add(3)), null, false)
                        .applyTo(p);
            }
            if (p.getListing().getInstructionAt(entry) != null) {
                // A derived D1 that tail-branches to this stub has it in its body as an
                // extra range, and createFunction refuses an address another body holds --
                // which is why every entry importing a code.bin destructor ended as a bare
                // label. Take the stub out of that body first.
                cutFromHost(p, entry, entry.add(7));
                // The body is the one instruction, as Ghidra makes it for every other entry;
                // the literal is data. (An 8-byte body here made 26 entries export at size 8
                // beside 578 at size 4.)
                f = p.getFunctionManager().createFunction(null, entry,
                        new AddressSet(entry, entry.add(3)), SourceType.DEFAULT);
            }
        }
        if (f == null) {
            if (name != null) st.createLabel(entry, name, p.getGlobalNamespace(), SourceType.ANALYSIS);
            return name != null;
        }
        if (f.isThunk()) {
            // A thunk to an *external* function sits in the library's namespace
            // (|static|::thunk_EXT_FUN_001cb8fc) with a default name, and in ModuleAmiiboCamera
            // every entry importing a code.bin destructor stayed exactly that: un-thunking
            // and renaming in place did not take, so 643 entries had no row. Replace the
            // function outright -- same entry, the stub's own 8 bytes.
            FunctionManager fm = p.getFunctionManager();
            fm.removeFunction(entry);
            cutFromHost(p, entry, entry.add(7));
            f = fm.createFunction(null, entry, new AddressSet(entry, entry.add(3)),
                    SourceType.DEFAULT);
        }
        if (name == null) {
            if (f.getSymbol().getSource() != SourceType.DEFAULT
                    && (f.getName().startsWith("plt_") || f.getName().contains("@"))) {
                f.setName(null, SourceType.DEFAULT);
            }
            return false;
        }
        if (!f.getName().equals(name) || !f.getParentNamespace().isGlobal()) {
            f.getSymbol().setNameAndNamespace(name, p.getGlobalNamespace(), SourceType.ANALYSIS);
        }
        return true;
    }

    /**
     * Remove [from, to] from any other function's body that holds part of it: a stub
     * absorbed as an extra range by a function that branches to it.
     */
    private static void cutFromHost(Program p, Address from, Address to) {
        FunctionManager fm = p.getFunctionManager();
        for (Address a : new Address[]{from, to}) {
            Function host = fm.getFunctionContaining(a);
            if (host == null || host.getEntryPoint().equals(from)) continue;
            AddressSetView kept = host.getBody().subtract(new AddressSet(from, to));
            if (kept.isEmpty() || !kept.contains(host.getEntryPoint())) continue;
            try {
                host.setBody(kept);
            } catch (Exception e) {
                // Leave it; createFunction will say so.
            }
        }
    }

    /**
     * Re-derive every linker veneer's name from its target's current name, last. armlink
     * names a veneer after its target symbol, and the targets are named by the pipeline --
     * after the veneer pass ran -- so all 74 of code.bin's still embedded FUN_…. The
     * kind prefix ($Ven$AT$I$$ etc.) is kept; only the target part is looked up again.
     */
    public static String renameVeneers(Program p) {
        int renamed = 0, current = 0;
        List<Function> veneers = new ArrayList<>();
        for (Function f : p.getFunctionManager().getFunctions(true)) {
            if (f.getSymbol().getName().startsWith("$Ven$")) veneers.add(f);
        }
        Memory m = p.getMemory();
        for (Function f : veneers) {
            String name = f.getSymbol().getName();
            int cut = name.indexOf("$$", 5);
            if (cut < 0) continue;
            String kind = name.substring(0, cut + 2);
            Address e = f.getEntryPoint();
            Address target;
            try {
                switch (kind) {
                    // ADR r12,{pc}+NN: target = veneer + 8 + NN, Thumb bit in NN's low bit
                    case "$Ven$AT$I$$" ->
                            target = e.getNewAddress((e.getOffset() + 8L + (m.getInt(e) & 0xff)) & ~1L);
                    case "$Ven$AT$L$$", "$Ven$AA$L$$" ->
                            target = e.getNewAddress(Integer.toUnsignedLong(m.getInt(e.add(4))) & ~1L);
                    case "$Ven$TA$I$$" -> target = e.add(4);
                    default -> { continue; }
                }
            } catch (Exception ex) {
                continue;
            }
            String t = veneerTarget(p, target);
            if (t == null) continue;
            String want = kind + t;
            if (want.equals(name)) { current++; continue; }
            try {
                f.getSymbol().setNameAndNamespace(want, p.getGlobalNamespace(), SourceType.ANALYSIS);
                renamed++;
            } catch (Exception ex) {
                // Keep the old name; it still says which veneer this is.
            }
        }
        return String.format("Veneers named last:     %d renamed from their target's current " +
                "name, %d already current", renamed, current);
    }

    /** A veneer target's name: a _Z one if any, else a real one, else its function name. */
    private static String veneerTarget(Program p, Address target) {
        String real = null;
        for (Symbol s : p.getSymbolTable().getSymbols(target)) {
            String n = s.getName();
            if (s.getSource() == SourceType.DEFAULT) continue;
            if (n.startsWith("_Z")) return n;
            if (real == null && !n.startsWith("$Ven$") && !isAutoLabel(n)) real = n;
        }
        if (real != null) return real;
        Function tf = p.getFunctionManager().getFunctionAt(target);
        if (tf == null) return null;
        if (tf.isThunk() && tf.getSymbol().getSource() == SourceType.DEFAULT) {
            return String.format("FUN_%08x", target.getOffset());
        }
        return tf.getName();
    }

    /**
     * Re-derive every PLT entry's name from its target's current name. For CROLink, after
     * all modules have been named: code.bin's pass runs first and would otherwise embed the
     * CRO targets' names as they stood before the CROs were processed.
     */
    public static String renamePltEntries(Program p,
                                          java.util.function.Function<String, Program> openByPath) {
        int renamed = 0, unchanged = 0, noRecord = 0, failed = 0;
        List<String> failures = new ArrayList<>();
        Memory m = p.getMemory();
        for (MemoryBlock block : m.getBlocks()) {
            if (!block.isInitialized() || !block.isExecute()) continue;
            long start = (block.getStart().getOffset() + 3) & ~3L;
            long end = block.getEnd().getOffset();
            for (long off = start; off + 8 <= end + 1; off += 4) {
                Address at = block.getStart().getNewAddress(off);
                try {
                    if (m.getInt(at) != 0xe51ff004) continue;
                    String name = pltName(p, at, openByPath);
                    if (name == null) { noRecord++; continue; }
                    Function f = p.getFunctionManager().getFunctionAt(at);
                    // A thunk reports its target's name, so equality there proves nothing.
                    if (f != null && !f.isThunk() && f.getName().equals(name)
                            && f.getParentNamespace().isGlobal()) {
                        unchanged++;
                        continue;
                    }
                    String before = (f == null) ? "no function"
                            : (f.isThunk() ? "thunk " : "function ") + f.getName(true);
                    if (applyPltName(p, at, name)) renamed++;
                    Function after = p.getFunctionManager().getFunctionAt(at);
                    if (after == null || after.isThunk() || !after.getName().equals(name)) {
                        failed++;
                        if (failures.size() < 5) {
                            failures.add(at + ": wanted " + name + "; before: " + before
                                    + "; after: " + (after == null ? "no function"
                                    : (after.isThunk() ? "thunk " : "function ")
                                      + after.getName(true)));
                        }
                    }
                } catch (Exception e) {
                    // One unnameable entry; the rest still get done -- but say why.
                    failed++;
                    if (failures.size() < 5) {
                        failures.add(at + ": " + e.getClass().getSimpleName() + ": "
                                + e.getMessage());
                    }
                }
            }
        }
        String s = String.format("PLT names:              %d renamed from their target's current " +
                "name, %d already current, %d long-form stubs with no import record left alone, " +
                "%d could not be renamed", renamed, unchanged, noRecord, failed);
        for (String f : failures) s += "\n        " + f;
        return s;
    }

    /**
     * Every address worth testing for a veneer or an import stub.
     *
     * <p>Not the function list. Ghidra creates a function only where control flow it has
     * already followed reaches one, and nothing in the disassembled code calls most of
     * these: 405 of the 604 PLT entries and most of the veneers have no function at all,
     * so a walk over functions named a third of the PLT and 18 of the 74 veneers. A label
     * does not need a function, and the encodings are in the bytes either way.
     *
     * <p>Scanned at a two-byte stride, because the Thumb-to-ARM form is two-byte aligned.
     */
    private List<Address> veneerCandidates() {
        List<Address> out = new ArrayList<>();
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || !block.isExecute()) continue;
            long start = block.getStart().getOffset();
            long end = block.getEnd().getOffset();
            for (long off = start; off + 8 <= end; off += 2) {
                try {
                    Address at = toAddress(off);
                    boolean hit;
                    // The file's bytes, not memory's. Memory at 0x301560 and 0x838768 holds
                    // "LDR pc,[pc,#-4] ; DCD 0x101e0f" written over the image after load --
                    // the file has plain B instructions there -- and matching on memory
                    // named both as armlink veneers that armlink never made.
                    if ((off & 3) == 0) {
                        int first = rawInt(at);
                        hit = first == 0xe51ff004
                                || ((first & 0xffffff00) == 0xe28fc000
                                    && rawInt(at.add(4)) == 0xe12fff1c);
                    } else {
                        hit = false;
                    }
                    if (!hit) {
                        hit = rawShort(at) == 0x4778 && rawShort(at.add(2)) == 0x46c0;
                    }
                    if (!hit) continue;
                    // No "inside another function" filter. These encodings occur nowhere
                    // in ACNL's .text but the 74 veneers and the PLT (checked against the
                    // raw file), and three of the veneers are exactly the ones Ghidra ran
                    // a preceding function's body across -- the filter hid the boundary
                    // error along with the veneer. nameLinkerVeneers cuts them back out.
                    out.add(at);
                } catch (Exception e) {
                    // Unreadable word; keep going.
                }
            }
        }
        return out;
    }

    /**
     * Label one PLT entry. One pattern for all of them: where the import record names the
     * symbol the name says so, where it only knows a module and an offset so does the
     * name, and where the record is missing the address stands in. armlink writes no
     * symbol here at all, so every one of these is an addition, and what makes them useful
     * is that they are recognisable as a set.
     */
    private void nameImportStub(Address entry) {
        // A $Ven$ label an earlier run put here is wrong twice over: these are not
        // veneers, and the name it embedded came from the loader's handler.
        for (Symbol sym : symTab.getSymbols(entry)) {
            if (sym.getName().startsWith("$Ven$")
                    && sym.getSource() == SourceType.ANALYSIS) {
                sym.delete();
            }
        }
        clearLiteralCode(entry.add(4));
        // No record, no name: the entry keeps Ghidra's default, for someone to work out.
        String plt = importStubName(entry);
        if (plt == null) pltEntriesAnonymous++;
        // Each entry is a function, and its name is the function's own. A label beside a
        // FUN_ left the default name primary on 38 entries, and the 349 with no function at
        // all -- nothing disassembled calls them -- never appeared in the symbol export,
        // which lists functions. One pattern for all 604 means one representation too.
        try {
            ensureFunction(entry, false);
            applyPltName(program, entry, plt);
            pltEntriesNamed++;
        } catch (Exception e) {
            script.printf("    WARNING: could not name PLT entry %s: %s\n", entry,
                    e.getMessage());
            pltEntriesUnnamed++;
        }
    }

    private int literalFunctionsRemoved = 0;

    /**
     * A PLT entry's second word is its literal, never an entry point. In the CROs a function
     * sat on it wherever something had pointed there -- a vbase offset read as a vtable slot
     * (0x32c in ModuleMusFish, "SealifeMuseumInfoHioNode::VF03") -- and disassembling the
     * word is what took CRXLibrary's import record off it, leaving the stub unrecognisable
     * as an import. The function, its instruction and any class name on it go; a label
     * CRXLibrary imported stays.
     */
    private void clearLiteralCode(Address literal) {
        try {
            Function f = program.getFunctionManager().getFunctionAt(literal);
            if (f != null) {
                program.getFunctionManager().removeFunction(literal);
                literalFunctionsRemoved++;
            }
            if (program.getListing().getInstructionAt(literal) != null) {
                // Clearing a code unit takes the references *from* it too, and on a PLT
                // literal that is the import record -- the only thing saying what the entry
                // calls. Keep them across the clear.
                List<Reference> keep = new ArrayList<>();
                for (Reference r : program.getReferenceManager().getReferencesFrom(literal)) {
                    if (r instanceof ExternalReference) keep.add(r);
                }
                program.getListing().clearCodeUnits(literal, literal.add(PTR_SIZE - 1), false);
                for (Reference r : keep) {
                    ExternalReference x = (ExternalReference) r;
                    ExternalLocation loc = x.getExternalLocation();
                    program.getReferenceManager().addExternalReference(literal,
                            loc.getLibraryName(), loc.getLabel(), loc.getAddress(),
                            r.getSource(), r.getOperandIndex(), r.getReferenceType());
                }
            }
            for (Symbol s : symTab.getSymbols(literal)) {
                if (s.getSource() == SourceType.IMPORTED) continue;
                if (s.getParentNamespace().isGlobal() && !isAutoLabel(s.getName())) continue;
                s.delete();
            }
        } catch (Exception e) {
            script.printf("    WARNING: could not clear code off the PLT literal at %s: %s\n",
                    literal, e.getMessage());
        }
    }

    private void nameLinkerVeneers() {
        int named = 0;
        literalFunctionsRemoved = 0;
        // The PLT first and in full. Its membership is settled by the run, so every entry
        // is named whether or not the scan below would reach it and whether or not Ghidra
        // has a function there.
        for (long off : new TreeSet<>(pltEntries)) {
            nameImportStub(toAddress(off));
        }
        List<Address> candidates = veneerCandidates();
        dropStaleVeneerNames(candidates);
        for (Address entry : candidates) {
            // An import stub before anything else: it shares the long form's bytes, so
            // the veneer test below would match it and name it after a literal that is
            // the loader's handler rather than any target.
            if (isImportStub(entry)) continue;    // already done, above
            // No filter on the current name. A Ghidra thunk reports the name of what it
            // forwards to, so a veneer reaching an already-named function is called
            // something like AcFtr::D1 rather than FUN_*, and gating on FUN_/thunk_ threw
            // exactly those away -- which is why only 6 of several hundred candidates
            // matched. The exact encoding is the whole test, and this only ever *adds* a
            // label, so a function that already has a good name keeps it.

            String kind = null;
            Address target = null;
            try {
                int first = rawInt(entry);
                if (first == 0xe51ff004) {
                    // LDR pc,[pc,#-4] ; DCD target. The bytes are identical for the ARM
                    // and interworking long forms -- the kind is carried by the literal's
                    // low bit, which is the Thumb flag on the target.
                    long literal = Integer.toUnsignedLong(rawInt(entry.add(4)));
                    kind = ((literal & 1L) != 0) ? "$Ven$AT$L$$" : "$Ven$AA$L$$";
                    target = toAddress(literal & ~1L);
                } else if ((first & 0xffffff00) == 0xe28fc000
                        && rawInt(entry.add(4)) == 0xe12fff1c) {
                    // ADR r12,{pc}+imm ; BX r12. armlink reserves one inline slot in
                    // front of each Thumb section; the immediate is 1 + the target's
                    // offset *within* that section, so it is #9 only when the target is
                    // the section's first instruction. A mid-section target can claim the
                    // slot when nothing before it has -- probe case E gives #0xd for a
                    // target 4 bytes in, and ACNL's 0x101a00 gives #0xb for 0x101a12, ten
                    // bytes into the Thumb section at 0x101a08. So the immediate is the
                    // whole answer and must be read, not assumed. Its low bit is the
                    // Thumb flag, which is why every value here is odd.
                    kind = "$Ven$AT$I$$";
                    target = toAddress((entry.getOffset() + 8L + (first & 0xff)) & ~1L);
                } else if (rawShort(entry) == 0x4778
                        && rawShort(entry.add(2)) == 0x46c0) {
                    kind = "$Ven$TA$I$$";
                    target = entry.add(4);
                }
            } catch (Exception e) {
                continue;
            }
            if (kind == null || target == null) continue;   // the scan only yields matches

            // A veneer is a function of its own, and so is what it reaches. 25 of ACNL's 74
            // had nothing decoded at either end, and 3 sat inside the body of the function
            // before them -- a function boundary wrong, which costs more than any name.
            boolean veneerThumb = kind.equals("$Ven$TA$I$$");
            boolean targetThumb = kind.startsWith("$Ven$AT");
            splitOutOf(entry, veneerThumb ? 4 : 8);
            ensureFunction(entry, veneerThumb);
            ensureFunction(target, targetThumb);

            // armlink embeds the target's name. Where the target has no recovered name yet
            // its current one stands in, and is revised on the next run: the label below is
            // replaced whenever the name it embeds is no longer the target's.
            String targetName = veneerTargetName(target);
            if (targetName == null) {
                Function tf = program.getListing().getFunctionAt(target);
                if (tf != null) targetName = tf.getName();
                veneerTargetUnnamed++;
            }
            if (targetName == null) continue;
            String want = kind + targetName;
            boolean present = false;
            Function ownerFn = program.getListing().getFunctionAt(entry);
            for (Symbol s : symTab.getSymbols(entry)) {
                if (!s.getName().startsWith("$Ven$")) continue;
                if (s.getName().equals(want)) { present = true; continue; }
                if (ownerFn != null && s.equals(ownerFn.getSymbol())) continue;  // renamed below
                if (s.getSource() == SourceType.ANALYSIS) s.delete();
            }
            // The name goes on the veneer's function itself, un-thunked. Left as a Ghidra
            // thunk, its function name is its target's, and every export suffixed the
            // $Ven$ label with the address ($Ven$AT$I$$FUN_00100260_00100258).
            try {
                Function vf = program.getListing().getFunctionAt(entry);
                if (vf != null) {
                    if (vf.isThunk()) vf.setThunkedFunction(null);
                    if (!vf.getName().equals(want)) {
                        for (Symbol s : symTab.getSymbols(entry)) {
                            if (!s.equals(vf.getSymbol()) && s.getName().equals(want)) s.delete();
                        }
                        vf.getSymbol().setNameAndNamespace(want, program.getGlobalNamespace(),
                                SourceType.ANALYSIS);
                    }
                } else if (!present) {
                    symTab.createLabel(entry, want, program.getGlobalNamespace(),
                            SourceType.ANALYSIS).setPrimary();
                }
                named++;
            } catch (Exception e) {
                script.printf("    WARNING: could not name veneer %s as %s: %s\n", entry, want,
                        e.getMessage());
            }
        }
        script.printf("    Linker veneers:         %d named the way armlink names them, " +
                "from their exact encodings\n", named);
        if (pltEntriesNamed > 0 || pltEntriesUnnamed > 0) {
            script.printf("    BPABI import stubs:     %d in the PLT run, %d named from " +
                    "their import record, %d with no record left with their default name, " +
                    "%d could not be labelled%s\n", pltEntries.size(),
                    pltEntriesNamed - pltEntriesAnonymous, pltEntriesAnonymous,
                    pltEntriesUnnamed,
                    unresolvedImportHandler == null ? ""
                            : "; unresolved-import handler at " + unresolvedImportHandler);
        }
        if (literalFunctionsRemoved > 0) {
            script.printf("    BPABI import stubs:     %d functions removed from a stub's " +
                    "literal word, which is data\n", literalFunctionsRemoved);
        }
        if (veneerTargetUnnamed > 0 || veneersSplitOut > 0) {
            script.printf("    Linker veneers:         %d embed their target's default name "
                    + "until it has a recovered one; %d cut out of a function body that "
                    + "had run across them\n", veneerTargetUnnamed, veneersSplitOut);
        }
    }

    /**
     * Take a {@code $Ven$} name this pass wrote off any address that is no longer a veneer
     * candidate -- or that is a PLT entry -- so a rule that tightens also cleans up after
     * itself.
     */
    private void dropStaleVeneerNames(List<Address> candidates) {
        Set<Address> keep = new HashSet<>(candidates);
        List<Symbol> stale = new ArrayList<>();
        SymbolIterator it = symTab.getSymbolIterator("$Ven$*", true);
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.getSource() != SourceType.ANALYSIS) continue;
            Address a = s.getAddress();
            if (keep.contains(a) && !isImportStub(a)) continue;
            stale.add(s);
        }
        for (Symbol s : stale) {
            try {
                Function f = program.getListing().getFunctionAt(s.getAddress());
                if (f != null && s.equals(f.getSymbol())) {
                    f.setName(null, SourceType.DEFAULT);
                } else {
                    s.delete();
                }
            } catch (Exception e) {
                script.printf("    WARNING: could not drop stale %s: %s\n", s.getName(),
                        e.getMessage());
            }
        }
        if (!stale.isEmpty()) {
            script.printf("    Linker veneers:         %d stale $Ven$ names dropped from "
                    + "addresses that are not veneers\n", stale.size());
        }
    }

    /**
     * End a function that has swallowed a veneer just before it. armlink places a veneer
     * between sections, never inside a function, so a body running across one is Ghidra
     * following a fall-through that is not there.
     */
    private void splitOutOf(Address veneer, int length) {
        Function f = program.getListing().getFunctionContaining(veneer);
        if (f == null || f.getEntryPoint().equals(veneer)) return;
        try {
            AddressSet cut = new AddressSet(veneer, f.getBody().getMaxAddress());
            AddressSetView kept = f.getBody().subtract(cut);
            if (kept.isEmpty() || !kept.contains(f.getEntryPoint())) return;
            f.setBody(kept);
            veneersSplitOut++;
        } catch (Exception e) {
            script.printf("    WARNING: could not end %s before the veneer at %s: %s\n",
                    f.getName(), veneer, e.getMessage());
        }
    }

    private int veneersSplitOut = 0;

    /** The name a veneer should embed: a mangled one if there is one, else any real one. */
    private String veneerTargetName(Address target) {
        String fallback = null;
        for (Symbol s : symTab.getSymbols(target)) {
            String name = s.getName();
            if (name.startsWith("_Z")) return name;
            if (s.getSource() == SourceType.DEFAULT) continue;
            if (name.startsWith("$Ven$") || isAutoLabel(name)) continue;
            if (fallback == null) fallback = name;
        }
        return fallback;
    }

    /**
     * Give each class its D2, the base-object destructor.
     *
     * <p>Itanium splits a destructor three ways. Which of them share an address depends on
     * whether the class has virtual bases, and both cases were missing entirely:
     *
     * <ul>
     * <li><b>No virtual bases.</b> D1 and D2 are the <em>same function</em>, emitted once
     *     with two symbols on it. Which one armcc marks as sized and which as a zero-size
     *     alias varies between classes -- {@code _ZN7ProcessD1Ev} is the sized one, but for
     *     {@code ObjectResource} it is {@code D2} -- so they are equals, and both names
     *     belong on the address.</li>
     * <li><b>Virtual bases.</b> D2 is a separate function taking the VTT in r1, and the
     *     vtable holds D1. Under -Ospace D1 is {@code MOV r1,#0 ; B D2}, which is how it
     *     can be found. Only that exact shape counts: when the body is trivial D1 can
     *     branch straight to a <em>base's</em> D1 instead, and naming that D2 would put
     *     this class's symbol on another class's function.</li>
     * </ul>
     */
    private void emitBaseObjectDestructors() {
        int aliased = 0;
        int separate = 0;
        for (String className : processed) {
            Namespace ns = classNamespaces.get(className);
            Integer idx = dtorSlot.get(className);
            if (ns == null || idx == null) continue;
            List<Long> slots = vtableSlots.get(className);
            if (slots == null || idx < 0 || idx >= slots.size()) continue;
            long raw = slots.get(idx);
            if (raw == 0) continue;

            // The _ZTS spelling first, the same way planMangledName does, so the two
            // always agree about how a class is spelled.
            String d2 = structorFromTypeName(ns, "D2");
            if (d2 == null) d2 = mangle(ns, "D2");
            String d1 = structorFromTypeName(ns, "D1");
            if (d1 == null) d1 = mangle(ns, "D1");
            if (d2 == null || d1 == null) continue;
            Address d1Addr = toAddress(raw & ~1L);

            if (!hasVirtualBase(className)) {
                if (addAliasLabel(d1Addr, d2)) aliased++;
                // Which of the two armcc emits as the sized symbol -- and which the vtable
                // references -- is decided by whether the class is abstract, not by
                // declaration order or virtual-base use: ObjectResource and IPositionable
                // are abstract and size D2; Process and friends are concrete and size D1.
                makePrimary(d1Addr, hasPureVirtualSlot(className) ? d2 : d1);
                continue;
            }
            Address target = baseObjectDestructor(className, d1Addr);
            if (target != null && addAliasLabel(target, d2)) {
                ensureFunction(target, (raw & 1L) != 0);
                // A separate D2 is reached only through D1's branch, so no slot points at
                // it; without this the prune below would take the name straight back off.
                mangledAliasAddrs.add(target.getOffset());
                separate++;
            }
        }
        script.printf("    Base-object dtors:      %d D2 aliases on the class's D1, " +
                "%d separate D2 functions behind a virtual-base D1\n", aliased, separate);
    }

    /**
     * Name the destructor of a primary base that has no table of its own to be named from.
     *
     * <p>A complete-object destructor destroys members and then bases, in reverse
     * declaration order, so the <em>last</em> thing it does is destroy the base at offset
     * 0 -- and under {@code -Otime} that last call is a tail branch with {@code this}
     * still in r0. So when D1 of a class without virtual bases ends in an unconditional
     * {@code B X}, X is its primary base's base-object destructor, which for a class
     * without virtual bases is also its D1: one address, both names.
     *
     * <p>{@code AudioObjFurniture::D1} ({@code 0x2c4fe8}) runs {@code SoundObjFurniture::D1}
     * on its member at +8 and then does {@code b 0x324a10}; {@code AudioObjFurnitureBase}
     * has no REAL vtable, so nothing else names that address, and the address-order pass
     * put the derived class's D1 there instead. Used only for a base with no named
     * destructor, only when every deriving class that tail-branches agrees on one target,
     * and never onto a vtable slot target, a deallocator or a runtime routine.
     */
    private void nameBaseDestructorsFromTailCalls() {
        Map<String, Set<Address>> votes = new HashMap<>();
        Map<String, Set<String>> voters = new HashMap<>();
        Map<String, Boolean> thumbOf = new HashMap<>();
        for (String className : processed) {
            Integer idx = dtorSlot.get(className);
            List<Long> slots = vtableSlots.get(className);
            if (idx == null || slots == null || idx < 0 || idx >= slots.size()) continue;
            if (hasVirtualBase(className)) continue;
            List<BaseRef> bases = baseInfoMap.get(className);
            if (bases == null || bases.isEmpty()) continue;
            BaseRef primary = bases.get(0);
            if (primary.isVirtual() || primary.offset() != 0) continue;
            String base = primary.name();
            // A base with its own table is named from it; this is only for the rest.
            if (dtorSlot.containsKey(base) && vtableSlots.containsKey(base)) continue;
            if (!classNamespaces.containsKey(base)) continue;

            long raw = slots.get(idx);
            if (raw == 0) continue;
            Address d1 = toAddress(raw & ~1L);
            Function f = program.getListing().getFunctionAt(d1);
            if (f == null) continue;
            InstructionIterator back = program.getListing().getInstructions(f.getBody(), false);
            if (!back.hasNext()) continue;
            Instruction last = back.next();
            if (!last.getFlowType().isJump() || last.getFlowType().isConditional()
                    || last.getFlowType().isComputed()) {
                continue;
            }
            Address[] flows = last.getFlows();
            if (flows.length != 1 || f.getBody().contains(flows[0])) continue;
            Address t = flows[0];
            long off = t.getOffset();
            if (allSlotTargets.contains(off) || operatorDeleteAddrs.contains(off)
                    || pureVirtualChain.contains(off)) {
                continue;
            }
            // In a CRO the base usually lives in code.bin, so the tail branch lands on this
            // module's PLT entry for it. The entry is named from its import record
            // (<target>@<soname>); naming it as the base's destructor put the authentic-
            // looking _ZN7AcNpcSpD2Ev on ModuleCeremony's stub at 0x414.
            if (isImportStub(t) || hasImportRecord(t) || hasImportRecord(t.add(4))) continue;
            votes.computeIfAbsent(base, k -> new HashSet<>()).add(t);
            voters.computeIfAbsent(base, k -> new TreeSet<>()).add(className);
            thumbOf.put(base, (raw & 1L) != 0);
        }

        int named = 0, split = 0;
        for (Map.Entry<String, Set<Address>> e : votes.entrySet()) {
            if (e.getValue().size() != 1) {
                split++;
                script.printf("    WARNING: deriving classes of %s tail-branch to %d different "
                        + "addresses %s; naming none\n", e.getKey(), e.getValue().size(),
                        e.getValue());
                continue;
            }
            String base = e.getKey();
            Address t = e.getValue().iterator().next();
            Namespace ns = classNamespaces.get(base);
            String d1 = structorFromTypeName(ns, "D1");
            if (d1 == null) d1 = mangle(ns, "D1");
            String d2 = structorFromTypeName(ns, "D2");
            if (d2 == null) d2 = mangle(ns, "D2");
            if (d1 == null || d2 == null) continue;

            // Clear a deriving class's destructor name that an address-order pass left here:
            // it is the tail-call target, not the caller.
            Function tf = program.getListing().getFunctionAt(t);
            Symbol entry = (tf == null) ? null : tf.getSymbol();
            for (Symbol s : symTab.getSymbols(t)) {
                String n = s.getName();
                Namespace p = s.getParentNamespace();
                boolean derivedStructor = !p.isGlobal()
                        && voters.get(base).contains(p.getName(true))
                        && STRUCTOR_CODES.contains(n.replaceFirst("_[0-9a-f]{8}$", ""));
                boolean derivedMangled = n.startsWith("_Z")
                        && s.getSource() == SourceType.ANALYSIS
                        && !n.equals(d1) && !n.equals(d2)
                        && (n.endsWith("D1Ev") || n.endsWith("D2Ev") || n.endsWith("D0Ev"));
                if (!derivedStructor && !derivedMangled) continue;
                try {
                    if (s.equals(entry)) {
                        // An entry symbol cannot be deleted; move it to the base instead.
                        tf.setParentNamespace(ns);
                        tf.setName("D1", SourceType.ANALYSIS);
                    } else {
                        s.delete();
                    }
                } catch (Exception ex) {
                    script.printf("    WARNING: could not clear %s at %s: %s\n",
                            s.getName(true), t, ex.getMessage());
                }
            }
            nameForAbsentOwner(base, t, "D1", thumbOf.get(base));
            addAliasLabel(t, d1);
            addAliasLabel(t, d2);
            makePrimary(t, hasPureVirtualSlot(base) ? d2 : d1);
            mangledAliasAddrs.add(t.getOffset());
            named++;
        }
        if (named > 0 || split > 0) {
            script.printf("    Base dtors from tails:  %d primary bases with no table of their "
                    + "own named from the tail branch of their derived classes' D1 "
                    + "(%d left alone on disagreement)\n", named, split);
        }
    }

    /** True when any class in this one's base closure is inherited virtually. */
    private boolean hasVirtualBase(String className) {
        Set<String> seen = new HashSet<>();
        Deque<String> queue = new ArrayDeque<>();
        queue.add(className);
        while (!queue.isEmpty()) {
            String current = queue.poll();
            if (!seen.add(current)) continue;
            List<BaseRef> bases = baseInfoMap.get(current);
            if (bases == null) continue;
            for (BaseRef b : bases) {
                if (b.isVirtual()) return true;
                queue.add(b.name());
            }
        }
        return false;
    }

    /**
     * Find a class's separate base-object destructor.
     *
     * <p>Matching {@code MOV r1,#0 ; B D2} found none of ACNL's 20 candidates, because
     * that shape is {@code -Ospace} only and ACNL is built {@code -Otime}: there D1 has
     * D2's body inlined and never calls it. The reliable marker is D2's own entry test.
     * D2 takes the VTT in r1, and r1 == 0 means "complete object", so every build of D2
     * begins by comparing r1 with zero and loading {@code _ZTT<cls>} under that condition.
     * D1 either zeroes r1 and branches ({@code -Ospace}) or loads the VTT unconditionally
     * with no r1 test ({@code -Otime}), so the test tells them apart in both builds.
     *
     * <p>Null is a legitimate answer: with a trivial implicit destructor at {@code -O3
     * -Otime} armcc emits no D2 at all.
     */
    private Address baseObjectDestructor(String className, Address d1Addr) {
        Address viaBranch = movZeroBranchTarget(d1Addr);
        if (viaBranch != null) return viaBranch;      // the -Ospace form, when present

        if (vtableScan == null) return null;
        Address vttStart = null;
        for (VtableScan.Vtt vtt : vtableScan.vtts()) {
            if (className.equals(vtt.ownerClass())) { vttStart = vtt.start(); break; }
        }
        if (vttStart == null) return null;

        // Whoever reads this class's VTT and tests r1 against zero is its D2.
        Address found = null;
        for (Reference ref : program.getReferenceManager().getReferencesTo(vttStart)) {
            Function func = program.getListing().getFunctionContaining(ref.getFromAddress());
            if (func == null) continue;
            Address entry = func.getEntryPoint();
            if (entry.equals(d1Addr)) continue;       // D1 reads it too, under -Otime
            if (!comparesR1WithZero(func)) continue;
            if (found != null && !found.equals(entry)) return null;   // ambiguous
            found = entry;
        }
        return found;
    }

    /** True when the function tests r1 against zero in its opening instructions. */
    private boolean comparesR1WithZero(Function func) {
        Register r1 = program.getLanguage().getRegister("r1");
        if (r1 == null) return false;
        int seen = 0;
        for (Instruction inst : program.getListing().getInstructions(func.getBody(), true)) {
            if (++seen > 8) break;
            if (!inst.getMnemonicString().toLowerCase().startsWith("cmp")) continue;
            if (!r1.equals(inst.getRegister(0))) continue;
            Scalar value = inst.getScalar(1);
            if (value != null && value.getUnsignedValue() == 0) return true;
        }
        return false;
    }

    /** True when any slot of the class's own vtable is __cxa_pure_virtual. */
    private boolean hasPureVirtualSlot(String className) {
        if (pureVirtualAddr == 0) return false;
        List<List<Long>> subs = allVtableSlots.get(className);
        if (subs == null) return false;
        for (List<Long> slots : subs) {
            for (long raw : slots) {
                if ((raw & ~1L) == (pureVirtualAddr & ~1L)) return true;
            }
        }
        return false;
    }

    /** Make one of the names at an address the primary symbol, if it is there. */
    private void makePrimary(Address addr, String name) {
        for (Symbol sym : symTab.getSymbols(addr)) {
            if (!sym.getName().equals(name)) continue;
            try {
                sym.setPrimary();
            } catch (Exception e) {
                // A function symbol may refuse; the label is still present either way.
            }
            return;
        }
    }

    /**
     * The branch target of a body that is exactly {@code MOV r1,#0 ; B X}, else null.
     * Anything else -- a real destructor body, a branch without the r1 setup, a longer
     * preamble -- is not the forwarding shape and gives no D2.
     */
    private Address movZeroBranchTarget(Address d1Addr) {
        Function func = program.getListing().getFunctionAt(d1Addr);
        if (func == null) return null;
        Register r1 = program.getLanguage().getRegister("r1");
        if (r1 == null) return null;
        boolean sawMovZero = false;
        int seen = 0;
        for (Instruction inst : program.getListing().getInstructions(func.getBody(), true)) {
            if (++seen > 2) return null;
            String mnemonic = inst.getMnemonicString().toLowerCase();
            if (seen == 1) {
                if (!mnemonic.startsWith("mov")) return null;
                if (!r1.equals(inst.getRegister(0))) return null;
                Scalar value = inst.getScalar(1);
                if (value == null || value.getUnsignedValue() != 0) return null;
                sawMovZero = true;
                continue;
            }
            if (!sawMovZero || !mnemonic.equals("b")) return null;
            Address[] flows = inst.getFlows();
            if (flows.length != 1) return null;
            return flows[0];
        }
        return null;
    }

    /** Add a second name to an address, unless it is already there. */
    private boolean addAliasLabel(Address addr, String name) {
        for (Symbol s : symTab.getSymbols(addr)) {
            if (s.getName().equals(name)) return false;
        }
        try {
            symTab.createLabel(addr, name, program.getGlobalNamespace(),
                    SourceType.ANALYSIS);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Name a slot target whose owning class has no vtable group, and so is never walked.
     *
     * <p>Only ever writes over a default or one of this pass's own placeholders. A name
     * already sitting here in some other namespace came from somewhere better informed
     * than a slot index, and the ownership pass is a lower bound on the declaring class
     * rather than a proof, so it does not get to overrule one.
     */
    private void nameForAbsentOwner(String owner, Address funcAddr, String slotName,
                                    boolean thumb) {
        if (slotName == null) return;
        // A class with construction C tables has its own destructor pair on record there
        // (slots 0/1, the class's own functions -- q15_ctable_contents.py); a deriving
        // class's guess at where the pair sits must not compete with it. In ModuleMusFish
        // that guess put AcObjectBase's D1 on 0x4c00, a bx lr, beside the real one at
        // 0x4c24, and the conflict left both as placeholders.
        if (!namingFromCTable && STRUCTOR_CODES.contains(slotName)
                && hasConstructionCTable(owner)) {
            return;
        }
        Namespace ns = classNamespaces.get(owner);
        if (ns == null) ns = namespaceForForeignClass(owner);
        if (ns == null) return;

        for (Symbol s : symTab.getSymbols(funcAddr)) {
            if (s.getParentNamespace().isGlobal()) continue;
            if (s.getParentNamespace().getID() == ns.getID()) return;   // already ours
            if (!isPlaceholder(s.getName())) return;                    // better name wins
        }
        ensureFunction(funcAddr, thumb);
        try {
            symTab.createLabel(funcAddr, slotName, ns, SourceType.ANALYSIS);
            absentOwnerNamed++;
        } catch (Exception e) {
            // A duplicate here means another table already placed the same name; harmless.
        }
    }

    /**
     * A class namespace in this program for a class whose typeinfo lives in another module,
     * made on demand. collectNamespaces only knows classes with a typeinfo label here, but
     * an owner found by the ancestry walk can be a CRO class: esc::BsEscModelBase
     * (ModuleMiniGame0) is the least common ancestor of the four escape:: classes whose
     * code.bin tables list 0x4e0c34 and five more, and once its own base was resolved
     * those six names had nowhere to go. Only for a class the inheritance tree knows.
     */
    private Namespace namespaceForForeignClass(String owner) {
        if (!parentMap.containsKey(owner) && !childrenMap.containsKey(owner)) return null;
        try {
            Namespace ns = NamespaceUtils.createNamespaceHierarchy(owner, null, program,
                    SourceType.ANALYSIS);
            if (!(ns instanceof GhidraClass)) ns = NamespaceUtils.convertNamespaceToClass(ns);
            classNamespaces.put(owner, ns);
            return ns;
        } catch (Exception e) {
            script.println("    WARNING: could not make a namespace for " + owner + ": " + e);
            return null;
        }
    }

    /** "D0" / "D1" if some symbol here already carries that name, else null. */
    private String destructorKindAt(Address addr) {
        for (Symbol sym : symTab.getSymbols(addr)) {
            String name = sym.getName();
            if (name.equals("D0") || name.startsWith("D0_")) return "D0";
            if (name.equals("D1") || name.startsWith("D1_")) return "D1";
        }
        return null;
    }

    private void processSubVtable(String className, Namespace ns, Address start,
                                  List<Long> mySlots, List<Long> parentSlots,
                                  int subIdx, Set<Address> vtableWriters) throws Exception {
        int parentSlotCount = (parentSlots != null) ? parentSlots.size() : 0;
        AddressSpace addressSpace = program.getMinAddress().getAddressSpace();
        // The primary sub-vtable keeps the primary base's slot ordering, so a
        // destructor already located in that base is at the same index here.
        int inheritedDtorIdx = -1;
        if (subIdx == 0) {
            List<String> parents = parentMap.get(className);
            if (parents != null && !parents.isEmpty()) {
                inheritedDtorIdx = dtorSlot.getOrDefault(parents.getFirst(), -1);
            }
        }
        String[] slotNames =
                computeSlotNames(mySlots, start, subIdx, vtableWriters, inheritedDtorIdx,
                        className);
        if (subIdx == 0) {
            for (int i = 0; i < slotNames.length; i++) {
                if ("D1".equals(slotNames[i])) {
                    dtorSlot.put(className, i);     // so this class's children inherit it
                    break;
                }
            }
        }
        for (int i = 0; i < mySlots.size(); i++) {
            long funcPtr = mySlots.get(i);
            Address slotAddr = start.add(4L * i);
            if (isPureVirtualRef(slotAddr)) { pureVirtualCount++; continue; }
            if (funcPtr == 0) { skipCount++; continue; }
            boolean isExternal = false;
            for (Reference r : program.getReferenceManager().getReferencesFrom(slotAddr)) {
                if (r instanceof ExternalReference) { isExternal = true; break; }
            }
            if (isExternal) { skipCount++; continue; }
            if (i < parentSlotCount) {
                if (funcPtr == parentSlots.get(i)) { skipCount++; continue; }
            }
            Address funcAddr = addressSpace.getAddress(funcPtr & ~1L);

            // A slot target is a function entry whoever gets to name it, so it becomes one
            // here, before ownership decides the name. Skipping to the owner first left
            // 0x54c0d0 and 0x54c2bc -- sead::DualScreenMethodTreeMgr slots owned elsewhere --
            // as switch labels inside another function, with no function and no row.
            ensureFunction(funcAddr, (funcPtr & 1L) != 0);

            if (contestedTargets.contains(funcAddr.getOffset())) { skipCount++; continue; }

            // Somebody less derived declares this function, so it is theirs to name. Their
            // turn comes later in the topological walk, or has already been and gone.
            String owner = slotOwner.get(funcAddr.getOffset());
            if (owner != null && !owner.equals(className)) {
                slotsOwnedElsewhere++;
                // The owner is usually walked in its own turn. But the least common
                // ancestor often has no vtable group at all -- an abstract base whose
                // constructors were inlined loses its _ZTV to section elimination -- so
                // nothing would ever name the slot, and the old behaviour silently left
                // it with whichever subclass's name got there first. Name it here, in the
                // owner's namespace, at the same slot index: every table that inherits
                // the slot carries it at the index the declaring base fixed.
                if (!allVtableSlots.containsKey(owner)) {
                    nameForAbsentOwner(owner, funcAddr, slotNames[i], (funcPtr & 1L) != 0);
                }
                continue;
            }

            Function func = ensureFunction(funcAddr, (funcPtr & 1L) != 0);

            // Set calling convention to __thiscall
            if (func != null) {
                try {
                    if (!"__thiscall".equals(func.getCallingConventionName())) {
                        func.updateFunction("__thiscall",
                                null, List.of(),
                                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                                true, SourceType.USER_DEFINED);
                    }
                } catch (Exception e) { /* may already be set */ }
            }

            // Ghidra models a lone branch as a THUNK FUNCTION, and this used to take that
            // at face value and leave it as FUN_*, on the reasoning that such a thing is
            // usually a tail call belonging to some unrelated function.
            //
            // That is wrong for ARMCC. A 4-byte `B X` is an ordinary function with its own
            // real name: a destructor whose every level is trivial collapses to a branch
            // straight to the first non-trivial ancestor's, and armcc/armlink 4.1 have no
            // identical-code folding, so one address is one function belonging to one
            // class. Skipping them is why AcObjectBase's D1 stayed FUN_001f50a8 while its
            // D0 four words earlier was named.
            //
            // What makes naming them safe is that this is a vtable slot target whose owner
            // the pass above settled from every table in the image. Ghidra's thunk modelling
            // is still undone, because it would otherwise show the target's name here.
            if (func != null && func.isThunk()) {
                branchStubsSkipped++;
                func.setThunkedFunction(null);
            }

            boolean alreadyNamed = false;
            Namespace existingNs = null;
            for (Symbol s : symTab.getSymbols(funcAddr)) {
                if (s.getParentNamespace().isGlobal()) continue;
                // Our own placeholder for this same class is not a real name, or the
                // pass could never revise its output. One in another class's namespace
                // still counts, so inherited slots keep what they were given.
                if (s.getParentNamespace().getID() == ns.getID()
                        && isPlaceholder(s.getName())) continue;
                alreadyNamed = true;
                existingNs = s.getParentNamespace();
                break;
            }
            if (alreadyNamed) {
                String existingClassName = existingNs.getName(true);
                if (isAncestorOf(existingClassName, className)) {
                    skipCount++;
                    continue;
                }
                String common = findCommonAncestor(existingClassName, className);
                Symbol oldSym = null;
                for (Symbol s : symTab.getSymbols(funcAddr)) {
                    if (s.getParentNamespace().getID() == existingNs.getID()) {
                        oldSym = s;
                        break;
                    }
                }
                // Only hoist a meaningful name. A slot placeholder means nothing in the
                // ancestor, which numbers its own vtable differently, and hoisting them
                // collapses unrelated functions onto one name.
                if (common != null && oldSym != null && !isPlaceholder(oldSym.getName())) {
                    Namespace commonNs = classNamespaces.get(common);
                    if (commonNs == null && NamespaceUtils.getNamespacesByName(
                            program, program.getGlobalNamespace(), common)
                            .isEmpty()) {
                        try {
                            commonNs = createNamespace(program,
                                    program.getGlobalNamespace(), common);
                            classNamespaces.put(common, commonNs);
                        } catch (Exception e) {
                            script.println("    FAILED: could not create namespace " + common);
                        }
                    }
                    if (commonNs != null) {
                        String oldName = oldSym.getName();
                        oldSym.delete();
                        symTab.createLabel(funcAddr, oldName, commonNs,
                                SourceType.USER_DEFINED);
                        renameCount++;
                    }
                }
                skipCount++;
                continue;
            }

            String name = slotNames[i];
            try {
                SymbolTable symTab = program.getSymbolTable();
                // The function's own symbol: getSymbols() has no defined order, so
                // taking the first can land on a stray label instead and leave the
                // function untouched.
                Function nameFunc = program.getListing().getFunctionAt(funcAddr);
                Symbol sym = (nameFunc != null) ? nameFunc.getSymbol() : null;
                if (sym == null) {
                    Symbol[] syms = symTab.getSymbols(funcAddr);
                    if (syms != null && syms.length > 0) sym = syms[0];
                }
                if (sym != null) {
                    sym.setNamespace(ns);
                    String prefix = ns.getName() + "::";
                    if (isRenameable(sym.getName())) {
                        sym.setName(name, SourceType.USER_DEFINED);
                    }
                    String symName = sym.getName();
                    if (symName.contains(prefix)) {
                        String sliced = symName.substring(
                                symName.lastIndexOf(prefix) + prefix.length());
                        sym.setName(sliced, SourceType.USER_DEFINED);
                    }
                } else {
                    symTab.createLabel(funcAddr, name, ns, SourceType.USER_DEFINED);
                }
                renameCount++;
            } catch (Exception e) {
                script.println("ERROR: Could not create label " + ns.getName(true) + "::" + name);
            }
        }

        // Create pointer array for this sub-vtable
        if (start != null && !mySlots.isEmpty()) {
            try {
                int arraySize = mySlots.size();
                Address arrayEnd = start.add((long) arraySize * PTR_SIZE - 1);

                ReferenceManager refMgr = program.getReferenceManager();
                Map<Address, List<Reference>> savedExtRefs = new HashMap<>();
                for (int j = 0; j < arraySize; j++) {
                    Address slotAddr = start.add((long) j * PTR_SIZE);
                    for (Reference ref : refMgr.getReferencesFrom(slotAddr)) {
                        if (ref instanceof ExternalReference) {
                            savedExtRefs.computeIfAbsent(slotAddr, k -> new ArrayList<>())
                                    .add(ref);
                        }
                    }
                }

                program.getListing().clearCodeUnits(start, arrayEnd, true);

                for (Map.Entry<Address, List<Reference>> entry : savedExtRefs.entrySet()) {
                    for (Reference ref : entry.getValue()) {
                        if (ref instanceof ExternalReference extRef) {
                            refMgr.addExternalReference(
                                    entry.getKey(),
                                    extRef.getLibraryName(),
                                    extRef.getLabel(),
                                    extRef.getExternalLocation().getAddress(),
                                    extRef.getSource(),
                                    ref.getOperandIndex(),
                                    ref.getReferenceType());
                        }
                    }
                }
            } catch (Exception e) {
                script.println("WARNING: Could not create vtable array at " + start);
            }
        }
    }

    // Package-visible: ClassLayoutBuilder tells a vtable pointer from an ordinary
    // member by asking whether it points into this category.
    static final CategoryPath VTABLE_PATH = new CategoryPath("/vtables");
    private static final CategoryPath VTFUNC_PATH  = new CategoryPath("/vtables/functions");

    private DataType prepareBasicFuncDef(Program program) {
        DataTypeManager dtm = program.getDataTypeManager();
        int ptrSize = program.getDefaultPointerSize();
        FunctionDefinitionDataType generic = new FunctionDefinitionDataType(VTFUNC_PATH, "vfunc");
        generic.setReturnType(new PointerDataType(DataType.VOID, ptrSize));
        generic.setArguments(new ParameterDefinitionImpl("this",
                new PointerDataType(DataType.VOID, ptrSize), null));
        generic.setVarArgs(true);
        return new PointerDataType(dtm.resolve(generic, DataTypeConflictHandler.KEEP_HANDLER), ptrSize);
    }

    private void applyVtableStruct(Address point, Structure vt) throws InvalidInputException, DuplicateNameException {
        ReferenceManager refMgr = program.getReferenceManager();
        Map<Address, List<Reference>> saved = new HashMap<>();
        for (int j = 0; j * PTR_SIZE < vt.getLength(); j++) {
            Address a = point.add((long) j * PTR_SIZE);
            for (Reference ref : refMgr.getReferencesFrom(a)) {
                if (ref instanceof ExternalReference) {
                    saved.computeIfAbsent(a, k -> new ArrayList<>()).add(ref);
                }
            }
        }
        try {
            program.getListing().clearCodeUnits(point, point.add(vt.getLength() - 1L), true);
            program.getListing().createData(point, vt);
        } catch (Exception e) {
            script.println("WARNING: Could not apply vtable struct at " + point);
            return;
        }
        for (var e : saved.entrySet()) {
            for (Reference ref : e.getValue()) {
                if (ref instanceof ExternalReference ext) {
                    refMgr.addExternalReference(e.getKey(), ext.getLibraryName(), ext.getLabel(),
                            ext.getExternalLocation().getAddress(), ext.getSource(),
                            ref.getOperandIndex(), ref.getReferenceType());
                }
            }
        }
    }

    /**
     * The function slots on their own -- what a vptr actually points at, and so what
     * the class struct's vtbl field has to be a pointer to.
     */
    private Structure buildVfuncsStruct(DataTypeManager dtm, AddressSpace space, DataType vFuncPtr,
                                        String flat, int v, List<Long> slots, Address point)
            throws MemoryAccessException {
        String name = (v == 0) ? flat + "_vfuncs" : flat + "_vfuncs_" + v;
        StructureDataType s = new StructureDataType(VTABLE_PATH, name, 0, dtm);
        Set<String> used = new HashSet<>();
        for (int i = 0; i < slots.size(); i++) {
            s.add(vFuncPtr, fieldNameFor(space, point, slots.get(i), i, used), "slot " + i);
        }
        return (Structure) dtm.resolve(s, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    /**
     * Pointer to the typeinfo struct this RTTI slot names, when one has already been
     * applied there; a plain pointer otherwise.
     */
    private DataType typeinfoPtrFor(Address rttiSlot) {
        try {
            long tiAddr = Integer.toUnsignedLong(program.getMemory().getInt(rttiSlot));
            Address ti = program.getMinAddress().getAddressSpace().getAddress(tiAddr);
            Data d = program.getListing().getDataAt(ti);
            if (d != null && d.getDataType() instanceof Structure ts) {
                return new PointerDataType(ts, PTR_SIZE);
            }
        } catch (Exception e) { /* fall through to a generic pointer */ }
        return PointerDataType.dataType;
    }

    /**
     * Append one sub-vtable -- any virtual-base offsets, then offset-to-top, the RTTI
     * pointer and the function slots -- to a vtable struct. {@code suffixIdx}
     * distinguishes the fields of sub-vtables sharing one struct; pass 0 when the
     * sub-vtable gets a struct of its own.
     *
     * <p>The typeinfo pointer is read from the sub-table's own RTTI slot rather than
     * computed as {@code head + 4}: a class with virtual bases puts one offset word per
     * virtual base in front of offset-to-top, so the head is no longer a fixed distance
     * from anything.
     */
    private void addSubVtableFields(StructureDataType s, VtableScan.SubTable sub,
                                    Structure vfuncs, int suffixIdx) {
        String suffix = (suffixIdx == 0) ? "" : "_" + suffixIdx;
        String what = sub.hasVcallOffsets()
                ? "this-adjustment a _ZTv thunk reads for that slot; 0 when not overridden"
                : "offset to a virtual base subobject";
        for (int i = 0; i < sub.vbaseCount(); i++) {
            s.add(IntegerDataType.dataType, PTR_SIZE, sub.headerWordName(i) + suffix, what);
        }
        s.add(IntegerDataType.dataType, PTR_SIZE, "offset_to_top" + suffix, "offset-to-top");
        s.add(typeinfoPtrFor(sub.rttiSlot()), PTR_SIZE, "typeinfo" + suffix, "RTTI pointer");
        s.add(vfuncs, "funcs" + suffix, "virtual function slots");
    }

    private void buildVtableStructs() throws Exception {
        DataTypeManager dtm = program.getDataTypeManager();
        AddressSpace space = program.getMinAddress().getAddressSpace();
        DataType vFuncPtr = prepareBasicFuncDef(program);   // move this over from RTTIUtil
        int built = 0;

        for (Map.Entry<String, List<List<Long>>> entry : allVtableSlots.entrySet()) {
            String className = entry.getKey();
            List<List<Long>> subVtables = entry.getValue();
            List<Address> points = allVtableAddressPoints.get(className);
            List<Address> heads = allVtableHeads.get(className);
            if (points == null || points.size() != subVtables.size()) continue;
            if (heads == null || heads.size() != subVtables.size()) continue;

            Namespace ns = classNamespaces.get(className);
            if (ns == null) continue;
            GhidraClass cls;
            if (ns instanceof GhidraClass gc) {
                cls = gc;
            } else {
                try {
                    cls = symTab.convertNamespaceToClass(ns);
                } catch (Exception e) {
                    script.println("    WARNING: skipping vtable struct for " + className);
                    continue;
                }
            }

            String flat = cls.getName(true).replace("::", "_");

            // The function structs are the same either way, and the primary one is what
            // the class struct's vtbl points at.
            List<Structure> vfuncs = new ArrayList<>();
            boolean usable = true;
            for (int v = 0; v < subVtables.size(); v++) {
                if (subVtables.get(v).isEmpty() || heads.get(v) == null) {
                    usable = false;
                    break;
                }
                vfuncs.add(buildVfuncsStruct(dtm, space, vFuncPtr, flat, v,
                        subVtables.get(v), points.get(v)));
            }
            if (!usable) {
                script.println("    WARNING: skipping vtable struct for " + className +
                        " (empty sub-vtable or unreadable head)");
                continue;
            }

            // Sub-vtables in one group are one object -- the object _ZTV names -- so they
            // get one struct starting at the first head. A gap between them is not a
            // reason to split: the forward walk stops at the first word that does not
            // read as a function pointer, so a table holding null slots ends early and
            // leaves them unclaimed. Those bytes are still part of the object, and are
            // carried as padding rather than thrown away.
            boolean contiguous = true;
            long[] gapBefore = new long[subVtables.size()];
            for (int v = 1; v < subVtables.size(); v++) {
                Address expected = points.get(v - 1).add(4L * subVtables.get(v - 1).size());
                long gap = heads.get(v).getOffset() - expected.getOffset();
                if (gap < 0) {
                    contiguous = false;
                    break;
                }
                gapBefore[v] = gap;
            }

            List<VtableScan.SubTable> subs = allVtableSubTables.get(className);
            if (subs == null || subs.size() != subVtables.size()) {
                script.println("    WARNING: skipping vtable struct for " + className +
                        " (no sub-table geometry)");
                continue;
            }

            if (contiguous) {
                StructureDataType s = new StructureDataType(VTABLE_PATH, flat + "_vtable", 0, dtm);
                for (int v = 0; v < subVtables.size(); v++) {
                    if (gapBefore[v] > 0) {
                        s.add(new ArrayDataType(Undefined1DataType.dataType,
                                        (int) gapBefore[v], 1),
                                "unwalked_" + v,
                                "slots the forward walk could not confirm, or padding");
                    }
                    addSubVtableFields(s, subs.get(v), vfuncs.get(v), v);
                }
                Structure resolved = (Structure) dtm.resolve(s, DataTypeConflictHandler.REPLACE_HANDLER);
                applyVtableStruct(heads.getFirst(), resolved);
                built++;
            } else {
                script.println("    WARNING: " + className +
                        " has non-contiguous sub-vtables; typing each one separately");
                for (int v = 0; v < subVtables.size(); v++) {
                    String structName = (v == 0) ? flat + "_vtable" : flat + "_vtable_" + v;
                    StructureDataType s = new StructureDataType(VTABLE_PATH, structName, 0, dtm);
                    addSubVtableFields(s, subs.get(v), vfuncs.get(v), 0);
                    Structure resolved = (Structure) dtm.resolve(s, DataTypeConflictHandler.REPLACE_HANDLER);
                    applyVtableStruct(heads.get(v), resolved);
                    built++;
                }
            }

            classVfuncs.put(className, vfuncs);
            linkClassStruct(dtm, cls, vfuncs.getFirst());
        }
        script.printf("    Vtable structs built:   %d\n", built);
    }

    /**
     * Type the construction vtables the same way real ones are typed.
     *
     * <p>Construction vtables are excluded from naming for good reason -- their slots hold
     * the base's functions, so letting them name anything is what produced rounds of junk
     * {@code VF*_n} placeholders. But excluding them from <em>typing</em> was never
     * intended: it left tens of kilobytes of real, structured const data sitting in the
     * listing as undefined bytes, with the offset-to-top and typeinfo words unreadable and
     * the function slots carrying no references at all.
     *
     * <p>Each group gets a struct of its own rather than borrowing the base's. They are
     * very nearly the same bytes -- the leading words are identical -- but a construction
     * table's sub-tables do not line up one-for-one with the base's own, since they
     * describe the base as it sits inside the deriving class. Sharing a struct on that
     * resemblance would mean guessing which sub-table matched which; building fresh ones
     * cannot be wrong, and costs only type-manager entries.
     */
    private void buildConstructionVtableStructs() throws Exception {
        if (vtableScan == null) return;
        DataTypeManager dtm = program.getDataTypeManager();
        AddressSpace space = program.getMinAddress().getAddressSpace();
        DataType vFuncPtr = prepareBasicFuncDef(program);
        int built = 0;
        int skipped = 0;
        constructionStructNames.clear();

        for (VtableScan.VtableGroup group : vtableScan.groups()) {
            if (group.kind() != VtableScan.Kind.CONSTRUCTION) continue;
            List<VtableScan.SubTable> subs = group.subs();
            if (subs.isEmpty()) continue;

            String flat = constructionStructName(group);

            List<Structure> vfuncs = new ArrayList<>();
            boolean usable = true;
            for (int v = 0; v < subs.size(); v++) {
                if (subs.get(v).slots().isEmpty()) {
                    usable = false;
                    break;
                }
                vfuncs.add(buildVfuncsStruct(dtm, space, vFuncPtr, flat, v,
                        subs.get(v).slots(), subs.get(v).addressPoint()));
            }
            if (!usable) {
                skipped++;
                continue;
            }

            // Same reasoning as the real path: the sub-tables of one group are one object,
            // and a gap between them is unwalked slots or padding, not a reason to split.
            boolean contiguous = true;
            long[] gapBefore = new long[subs.size()];
            for (int v = 1; v < subs.size(); v++) {
                long gap = subs.get(v).head().getOffset() - subs.get(v - 1).end().getOffset();
                if (gap < 0) {
                    contiguous = false;
                    break;
                }
                gapBefore[v] = gap;
            }

            if (contiguous) {
                StructureDataType s =
                        new StructureDataType(VTABLE_PATH, flat + "_vtable", 0, dtm);
                for (int v = 0; v < subs.size(); v++) {
                    if (gapBefore[v] > 0) {
                        s.add(new ArrayDataType(Undefined1DataType.dataType,
                                        (int) gapBefore[v], 1),
                                "unwalked_" + v,
                                "slots the forward walk could not confirm, or padding");
                    }
                    addSubVtableFields(s, subs.get(v), vfuncs.get(v), v);
                }
                Structure resolved =
                        (Structure) dtm.resolve(s, DataTypeConflictHandler.REPLACE_HANDLER);
                applyVtableStruct(group.head(), resolved);
                built++;
            } else {
                script.println("    WARNING: construction vtable " + flat +
                        " has non-contiguous sub-tables; typing each one separately");
                for (int v = 0; v < subs.size(); v++) {
                    String structName = (v == 0) ? flat + "_vtable" : flat + "_vtable_" + v;
                    StructureDataType s =
                            new StructureDataType(VTABLE_PATH, structName, 0, dtm);
                    addSubVtableFields(s, subs.get(v), vfuncs.get(v), 0);
                    Structure resolved = (Structure) dtm.resolve(s,
                            DataTypeConflictHandler.REPLACE_HANDLER);
                    applyVtableStruct(subs.get(v).head(), resolved);
                    built++;
                }
            }
        }
        script.printf("    Construction vtables:   %d typed, %d skipped (empty sub-table)\n",
                built, skipped);
    }

    /**
     * The type-name stem for a construction vtable: {@code <Base>_in_<Derived>}, the same
     * thing {@code _ZT_C1_<Base><Derived>} says, with {@code _vbase} appended for the
     * {@code _ZT_B1_} table, which is a separate object describing the virtual base
     * subobject and so needs a name of its own rather than sharing the C table's.
     *
     * <p>An unattributed group -- one no VTT reached -- is named for its address instead,
     * so it still gets typed rather than left as undefined bytes over a naming problem.
     */
    private String constructionStructName(VtableScan.VtableGroup group) {
        String base = flatten(classNamespaces.get(group.className()), group.className());
        // Any non-zero offset-to-top means a base subobject, so it is a B table. Testing
        // for a negative one missed the +4 table at 0x8a269c, which a shared virtual base
        // sitting before the subobject makes legitimate (open answers Q3).
        String suffix = (group.primary().offsetToTop() != 0) ? "_vbase" : "";
        String derived = group.derivedOwner();
        String stem = (derived == null)
                ? base + "_ctor_at_" + Long.toHexString(group.head().getOffset()) + suffix
                : base + "_in_" + flatten(classNamespaces.get(derived), derived) + suffix;

        // One derived class can have two B tables carrying the same typeinfo -- one per
        // secondary base it inherits the virtual base through. AcFsFdShadow has two under
        // AcFishFieldBase, at 0x83e558 and 0x83e5b4, and they were getting the same struct
        // name; resolve() then replaced the first definition with the second, so the data
        // applied at the first head took the second's length. That is why their CSV sizes
        // were 0x30 and 0x54 when the rows span 92 and 104 bytes.
        if (!constructionStructNames.add(stem)) {
            stem = stem + "_at_" + Long.toHexString(group.head().getOffset());
            constructionStructNames.add(stem);
        }
        return stem;
    }

    /** Struct stems already handed out this run, so two groups never share one. */
    private final Set<String> constructionStructNames = new HashSet<>();

    /**
     * Point the class struct's vtbl field at the primary sub-vtable's function slots.
     * A vptr holds the address point, not the vtable head, so this must be the
     * functions-only struct rather than the one applied to memory.
     */
    private void linkClassStruct(DataTypeManager dtm, GhidraClass cls, Structure vt) {
        Structure cs = VariableUtilities.findExistingClassStruct(cls, dtm);
        if (cs == null) {
            Structure placeholder = VariableUtilities.findOrCreateClassStruct(cls, dtm);
            if (placeholder == null) {          // name collides with an unrelated data type
                script.println("    WARNING: no class struct available for " + cls.getName(true));
                return;
            }
            cs = (Structure) dtm.resolve(placeholder, DataTypeConflictHandler.KEEP_HANDLER);
        }

        DataType vtPtr = new PointerDataType(vt, PTR_SIZE);
        try {
            if (cs.getLength() < PTR_SIZE) {
                cs.insertAtOffset(0, vtPtr, PTR_SIZE, "vtbl", "vtable pointer");
            } else {
                cs.replaceAtOffset(0, vtPtr, PTR_SIZE, "vtbl", "vtable pointer");
            }
        } catch (Exception e) {
            script.println("    WARNING: could not set vtbl on " + cls.getName() + ": " + e.getMessage());
        }
    }

    private String fieldNameFor(AddressSpace space, Address point, long funcPtr,
                                int i, Set<String> used) throws MemoryAccessException {
        Address slotAddr = point.add(4L * i);
        String base = null;

        // external label first â€” an imported virtual also reads as funcPtr == 0
        for (Reference r : program.getReferenceManager().getReferencesFrom(slotAddr)) {
            if (r instanceof ExternalReference ext && ext.getLabel() != null) {
                base = ext.getLabel();
                break;
            }
        }
        if (base == null && (isPureVirtualRef(slotAddr) || funcPtr == 0)) {
            base = "__cxa_pure_virtual";
        }
        if (base == null) {
            Function f = program.getFunctionManager()
                    .getFunctionAt(space.getAddress(funcPtr & ~1L));
            if (f != null) base = f.getName();
        }
        if (base == null) base = "slot";

        base = base.replaceAll("[^A-Za-z0-9_]", "_");
        if (base.isEmpty() || Character.isDigit(base.charAt(0))) base = "_" + base;

        String name = base;
        int n = 1;
        while (!used.add(name)) name = base + "_" + (n++);   // overloads collide otherwise
        return name;
    }
}
