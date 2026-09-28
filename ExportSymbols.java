//@category 3DS
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.StreamSupport;

public class ExportSymbols extends GhidraScript {

    class SymbolData implements Comparable<SymbolData> {
        Address addr;
        String name;
        String namespace;
        String mode;
        long size;
        String segment;

        SymbolData(Address addr, String name, String namespace, String mode, long size, String segment) {
            this.addr = addr;
            this.name = name;
            this.namespace = namespace;
            this.mode = mode;
            this.size = size;
            this.segment = segment;
        }

        public int compareTo(SymbolData other) {
            return Math.toIntExact(this.addr.subtract(other.addr));
        }

        @Override
        public String toString() {
            return String.format("\"%s\",\"%s\",\"%s\",%s,%08x,\"%s\"",addr,name,namespace,mode,size,segment);
        }
    }

    @Override
    protected void run() throws Exception {

        boolean directory = askYesNo("Export in directory?","Should symbols from an entire directory be exported? (Otherwise, will operate on this program)");
        boolean unique = askYesNo("Create unique symbols?","Should the script export each symbol with a unique name (including the symbol address)?");
        // Both spellings live on the same address, and which one is primary depends only
        // on whether ToggleMangledNames was last run. Choosing here means the export no
        // longer depends on program state it has nothing to do with, and no longer
        // requires flipping every symbol in the program just to produce a file.
        namePreference = askChoice("Name spelling",
                "Which spelling should the Name column use? Both symbols exist at each " +
                        "address; \"As-is\" keeps whichever Ghidra has marked primary.",
                List.of(AS_IS, MANGLED, DEMANGLED), AS_IS);

        boolean merge = false;
        if (directory)
            merge = askYesNo("Merge symbols?","Would you like to merge all symbols into a single file?");

        if (directory && !merge) {
            DomainFolder folder = askProjectFolder("Select Directory to Symbolify");
            File outDir = askDirectory("Output directory", "OK");

            List<DomainFile> files_to_symbolify = getAllFilesInDirectory(folder);
            ProgramManager pman = getState().getTool().getService(ProgramManager.class);

            for (DomainFile file : files_to_symbolify) {
                if (monitor.isCancelled()) break;
                File outFile = new File(outDir, file.getName() + ".csv");
                List<SymbolData> symbols = extractFrom(pman, file, unique);
                if (symbols == null) continue;
                try (PrintWriter out = new PrintWriter(new FileWriter(outFile))) {
                    out.println("Location,Name,Namespace,Mode,Size,Segment");
                    for (SymbolData symbol : symbols) out.println(symbol);
                }
            }

        } else if (merge) {
            DomainFolder folder = askProjectFolder("Select Directory to Symbolify");
            File outFile = askFile("Output file", "OK");
            List<DomainFile> files_to_symbolify = getAllFilesInDirectory(folder);
            ProgramManager pman = getState().getTool().getService(ProgramManager.class);
            // Written module by module: holding every module's rows until the end kept all
            // of them alive at once for no reason.
            try (PrintWriter out = new PrintWriter(new FileWriter(outFile))) {
                out.println("Module,Location,Name,Namespace,Mode,Size,Segment");
                for (DomainFile file : files_to_symbolify) {
                    if (monitor.isCancelled()) break;
                    List<SymbolData> symbols = extractFrom(pman, file, unique);
                    if (symbols == null) continue;
                    for (SymbolData sd : symbols) {
                        out.printf("\"%s\",%s\n", file.getName(), sd.toString());
                    }
                }
            }
        } else {
            exportProgram(currentProgram, askFile("Output file", "OK"), unique);
        }

        reportForeignRanges();
        println("Done!");
    }

    // ---------------------------------------------------------------
    //  Entry points for another script (CROLink), which already holds the programs
    // ---------------------------------------------------------------

    public void setNamePreference(String preference) {
        namePreference = preference;
    }

    /** One program's rows, with the single-program header. */
    public void exportProgram(Program program, File outFile, boolean unique)
            throws IOException {
        try (PrintWriter out = new PrintWriter(new FileWriter(outFile))) {
            out.println("Location,Name,Namespace,Mode,Size,Segment");
            extractSymbols(program, unique).forEach(out::println);
        }
    }

    /** Every given program's rows in one file, with a Module column. */
    public void exportMerged(List<Program> programs, File outFile, boolean unique)
            throws IOException {
        try (PrintWriter out = new PrintWriter(new FileWriter(outFile))) {
            out.println("Module,Location,Name,Namespace,Mode,Size,Segment");
            for (Program p : programs) {
                if (monitor.isCancelled()) break;
                for (SymbolData sd : extractSymbols(p, unique)) {
                    out.printf("\"%s\",%s\n", p.getName(), sd.toString());
                }
            }
        }
    }

    static final String AS_IS = "As-is (whichever is primary)";
    static final String MANGLED = "Mangled (_Z...)";
    static final String DEMANGLED = "Demangled (Class::method)";

    private String namePreference = AS_IS;

    /**
     * The symbol at this address carrying the requested spelling, or the one given.
     *
     * <p>The pipeline writes both: {@code _ZN5AcFtrD1Ev} in the global namespace and
     * {@code AcFtr::D1} in the class's. Only one is primary at a time, so an export that
     * reads only the primary shows whichever ToggleMangledNames last selected. Everything
     * else about the row -- size, mode, segment -- belongs to the address rather than the
     * symbol, so only the name and namespace need to follow the choice.
     */
    private Symbol preferredSpelling(Symbol symbol) {
        if (AS_IS.equals(namePreference)) return symbol;
        boolean wantMangled = MANGLED.equals(namePreference);
        if (symbol.getName().startsWith("_Z") == wantMangled) return symbol;

        Symbol fallback = null;
        for (Symbol sibling : symbol.getProgram().getSymbolTable()
                .getSymbols(symbol.getAddress())) {
            if (sibling.getName().startsWith("_Z") != wantMangled) continue;
            if (sibling.getSource() == SourceType.DEFAULT) continue;
            // For the readable spelling, one sitting in a class namespace beats a bare
            // global label; for the mangled one, any _Z symbol is equally good.
            if (wantMangled || !sibling.getParentNamespace().isGlobal()) return sibling;
            if (fallback == null) fallback = sibling;
        }
        return (fallback != null) ? fallback : symbol;
    }

    List<SymbolData> extractSymbols(Program program, boolean unique) {

        Map<String, List<SymbolData>> symbolCounts = new HashMap<>();

        Register tmode = program.getProgramContext().getRegister("TMode");
        FunctionManager fm = program.getFunctionManager();
        ReferenceManager rm = program.getReferenceManager();
        Iterator<Symbol> iter = program.getSymbolTable().getAllSymbols(false);
        while (iter.hasNext()) {
            Symbol symbol = iter.next();
            if (!symbol.isPrimary() || symbol.isExternal()) continue;
            // Ghidra's switch-table labels (switchD, switchdataD_…, caseD_n, default in a
            // switchD_ namespace) are its own bookkeeping, never a linker symbol: 763 of
            // them were exported as 1-byte data rows.
            if (symbol.getParentNamespace().getName().startsWith("switchD_")
                    || symbol.getName().startsWith("switchdataD_")) {
                continue;
            }
            Address addr = symbol.getAddress();
            boolean hasExternalRef = Arrays.stream(rm.getReferencesFrom(addr))
                    .anyMatch(Reference::isExternalReference);
            // Skip what stands for another module's symbol: an import word, or a Ghidra
            // thunk that shows an external's name. Not a PLT entry, which is a function of
            // this image with a name of its own -- skipping those hid 372 of the 604.
            Function atAddr = fm.getFunctionAt(addr);
            Symbol chosen = preferredSpelling(symbol);
            // ...but a typeinfo or vtable of this module whose *first word* is an import (a
            // CRO _ZTI's ABI-vtable pointer, a _ZTV whose first slot is imported) is the
            // module's own object. Skipping those left all but 3 CRO _ZTI rows out.
            boolean ownObject = chosen.getName().startsWith("_ZT")
                    || hasObjectSibling(program, addr);
            if (hasExternalRef && (atAddr == null || atAddr.isThunk()) && !ownObject) continue;
            String name = chosen.getName(false);
            String namespace = chosen.getParentNamespace().getName(true);
            String mode = null;
            CodeUnit cu = program.getListing().getCodeUnitAt(addr);
            Function f = fm.getFunctionAt(addr);
            long size = 0;
            if (cu instanceof Instruction) {
                if (f == null) continue;
                if (f.isThunk() && f.getSymbol().getSource() == SourceType.DEFAULT) {
                    // A Ghidra thunk shows its target's name ("thunk_FUN_00100b8c"), which
                    // is nobody's symbol and repeats across every stub reaching one target,
                    // hence the _<addr> suffix it used to get. A lone B is an ordinary
                    // function (fixes doc, link-time layout): its own default name.
                    name = String.format("FUN_%08x", addr.getOffset());
                    namespace = "Global";
                } else if (unique && f.isThunk() && !f.getName()
                        .contains(f.getSymbol().getAddress().toString())) {
                    name += "_" + addr;
                }
                var rv = program.getProgramContext().getRegisterValue(tmode, addr);
                if (rv != null) {
                    BigInteger val = rv.getUnsignedValue();
                    mode = Objects.equals(val, BigInteger.ONE) ? "$t" : "$a";
                }
                size = (f.getBody().getNumAddressRanges() == 1)
                        ? f.getBody().getNumAddresses()
                        : contiguousExtent(program, f);
            } else if (cu instanceof Data) {
                var d = program.getListing().getDataAt(addr);
                if (d == null) continue;
                // The item's length, not its type's: a C string's type has no fixed length
                // (-1), which silently dropped every _ZTS row -- RTTIUtil labels and types
                // each typeinfo name string, and none of them reached the export.
                size = d.getLength();
                mode = "$d";
            } else if (cu == null && name.startsWith("_Z")) {
                // A mangled symbol in zero-initialised memory: no bytes in the file, so no
                // data unit to size it by. static.crs exports _ZNSs9__nullrefE at 0xaf7f30
                // that way; it is a real symbol and gets a row, sized as unknown (0).
                // (That address is not even in a memory block: the ZI region is not mapped.)
                MemoryBlock b = program.getMemory().getBlock(addr);
                if (b == null || !b.isExecute()) {
                    mode = "$d";
                    size = 0;
                }
            }
            if (mode == null || (size <= 0 && !"$d".equals(mode))) continue;
            if (size <= 0 && cu != null) continue;
            MemoryBlock segment = program.getMemory().getBlock(addr);
            String segName = ".text";
            if (segment != null) {
                segName = segment.getName();
            } else if ("$d".equals(mode) && cu == null) {
                segName = ".bss";      // zero-initialised data the loader did not map
            } else {
                printf("No block at address %s - The output of " +
                        "this symbol (%s) will likely be incorrect, as it was set " +
                        "to .text by default!\n", addr, symbol.getName());
            }
            // Key on the qualified name, not the leaf. Two classes both declaring a VF03,
            // or both having a ~Class, are different symbols that happen to share a last
            // component -- the Namespace column already tells them apart, so suffixing
            // them with an address says "these collide" when nothing does. Only a genuine
            // collision, one fully-qualified name at two addresses, earns the suffix.
            String qualified = namespace.isEmpty() ? name : namespace + "::" + name;
            symbolCounts.computeIfAbsent(qualified, k -> new ArrayList<>())
                    .add(new SymbolData(addr, name, namespace, mode, size, segName));
            // The other half of a C1/C2 or D1/D2 alias: one body, two symbols, and the
            // decomp's linker has to resolve a call to either. static.crs exports both at
            // 35 addresses (0x3076c8 = _ZNSsD1Ev and _ZNSsD2Ev); only one used to be written.
            String alias = structorAlias(program, addr, name);
            if (alias != null) {
                symbolCounts.computeIfAbsent(alias, k -> new ArrayList<>())
                        .add(new SymbolData(addr, alias, "Global", mode, size, segName));
            }
        }

        List<SymbolData> symbols = new ArrayList<>();
        if (unique) {
            for (List<SymbolData> sdList : symbolCounts.values()) {
                if (sdList.size() > 1) {
                    for (SymbolData sd : sdList) {
                        sd.name += String.format("_%s", sd.addr);
                        symbols.add(sd);
                    }
                } else {
                    symbols.add(sdList.getFirst());
                }
            }
        } else {
            symbolCounts.values().forEach(symbols::addAll);
        }
        symbols.sort(SymbolData::compareTo);
        return symbols;
    }

    /**
     * One module's rows, with the program held only while they are read.
     *
     * <p>{@code openCachedProgram} registers this script as a consumer of the program, and
     * only {@code release} gives that back. The old {@code closeProgram} call closed
     * nothing -- a cached program is not open in the tool -- so every module in the folder
     * stayed in memory until Ghidra exited, and each directory export added another
     * consumer to all of them.
     */
    private List<SymbolData> extractFrom(ProgramManager pman, DomainFile file, boolean unique) {
        if (!Program.class.isAssignableFrom(file.getDomainObjectClass())) return null;
        Program p = pman.openCachedProgram(file, this);
        if (p == null) {
            printerr("Could not open " + file.getPathname() + "; skipped");
            return null;
        }
        try {
            return extractSymbols(p, unique);
        } finally {
            p.release(this);
        }
    }

    // The structor code is followed by E, or by I when the constructor is a template
    // (_ZNSaI…EC1IcEERKSaIT_E, which static.crs exports as a C1/C2 pair at 0x11c45e).
    private static final java.util.regex.Pattern STRUCTOR =
            java.util.regex.Pattern.compile("^(_Z.*)([CD])([12])([EI].*)$");

    /**
     * The partner of a mangled C1/C2/D1/D2 name when a symbol with that name sits at the
     * same address, else null. Only mangled names: a demangled spelling does not say which
     * variant it is.
     */
    private static String structorAlias(Program program, Address addr, String name) {
        java.util.regex.Matcher m = STRUCTOR.matcher(name);
        if (!m.matches()) return null;
        String partner = m.group(1) + m.group(2) + (m.group(3).equals("1") ? "2" : "1")
                + m.group(4);
        for (Symbol s : program.getSymbolTable().getSymbols(addr)) {
            if (s.getSource() != SourceType.DEFAULT && s.getName().equals(partner)) {
                return partner;
            }
        }
        return null;
    }

    /** A _ZTI/_ZTV/_ZTS/_ZTT/_ZT_ symbol at the address, whatever is primary. */
    private static boolean hasObjectSibling(Program program, Address addr) {
        for (Symbol s : program.getSymbolTable().getSymbols(addr)) {
            if (s.getName().startsWith("_ZT")) return true;
        }
        return false;
    }

    /** Body ranges left out of a function's row because other code separates them. */
    private int foreignRanges = 0;

    public void reportForeignRanges() {
        if (foreignRanges > 0) {
            println(foreignRanges + " function body ranges left out: other code separates " +
                    "them from their function's entry, so they are not part of it");
        }
    }

    /**
     * A function's size as armcc laid it out: one contiguous run from the entry.
     *
     * <p>Ghidra's body leaves out the data inside a function, so an inline jump table
     * (ldrlo pc,[pc,r0,lsl #2] followed by the case words) or a literal pool splits one
     * function into several ranges. Each extra range used to become a row of its own,
     * named {@code <name>_<addr>} -- 36 "names at several addresses" in the CROs alone,
     * e.g. {@code nnroControlObject__00011658}, which is nnroControlObject_'s own switch
     * cases after a five-word table. Ranges joined only by bytes that hold no instruction
     * are the same function; a range reached across someone else's code is not, gets no
     * row and no copy of the name, and is counted.
     */
    private long contiguousExtent(Program program, Function f) {
        Address entry = f.getEntryPoint();
        List<AddressRange> ranges = new ArrayList<>();
        f.getBody().getAddressRanges().forEachRemaining(ranges::add);
        ranges.sort(null);
        Address end = null;
        for (AddressRange r : ranges) {
            if (end == null) {
                if (r.contains(entry)) end = r.getMaxAddress();
                else if (r.getMaxAddress().compareTo(entry) < 0) foreignRanges++;
                continue;
            }
            Address gapStart = end.next();
            Address gapEnd = r.getMinAddress().previous();
            boolean dataOnly = gapStart == null || gapEnd == null
                    || gapStart.compareTo(gapEnd) > 0
                    || !program.getListing().getInstructions(
                            new ghidra.program.model.address.AddressSet(gapStart, gapEnd), true)
                            .hasNext();
            if (!dataOnly) { foreignRanges++; continue; }
            end = r.getMaxAddress();
        }
        return (end == null) ? f.getBody().getNumAddresses() : end.subtract(entry) + 1;
    }

    List<DomainFile> getAllFilesInDirectory(DomainFolder root) {
        List<DomainFile> files = new ArrayList<>();
        for (DomainFolder subfolder : root.getFolders()) {
            files.addAll(List.of(subfolder.getFiles()));
        }
        files.addAll(List.of(root.getFiles()));
        return files;
    }
}
