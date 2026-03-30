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
import ghidra.program.model.symbol.Symbol;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.StreamSupport;

public class ExportSymbols extends GhidraScript {

    class SymbolData implements Comparable<SymbolData> {
        Address addr;
        String name;
        String mode;
        long size;
        String segment;

        SymbolData(Address addr, String name, String mode, long size, String segment) {
            this.addr = addr;
            this.name = name;
            this.mode = mode;
            this.size = size;
            this.segment = segment;
        }

        public int compareTo(SymbolData other) {
            return Math.toIntExact(this.addr.subtract(other.addr));
        }

        @Override
        public String toString() {
            return String.format("\"%s\",\"%s\",%s,%08x,\"%s\"",addr,name,mode,size,segment);
        }
    }

    @Override
    protected void run() throws Exception {

        boolean directory = askYesNo("Export in directory?","Should symbols from an entire directory be exported? (Otherwise, will operate on this program)");
        boolean unique = askYesNo("Create unique symbols?","Should the script export each symbol with a unique name (including the symbol address)?");
        boolean merge = false;
        if (directory)
            merge = askYesNo("Merge symbols?","Would you like to merge all symbols into a single file?");

        if (directory && !merge) {
            DomainFolder folder = askProjectFolder("Select Directory to Symbolify");
            File outDir = askDirectory("Output directory", "OK");

            List<DomainFile> files_to_symbolify = getAllFilesInDirectory(folder);
            ProgramManager pman = getState().getTool().getService(ProgramManager.class);

            for (DomainFile file : files_to_symbolify) {
                File outFile = new File(outDir, file.getName() + ".csv");
                PrintWriter out = new PrintWriter(new FileWriter(outFile));
                Program p = pman.openCachedProgram(file, this);

                out.println("Location,Name,Mode,Size,Segment");
                List<SymbolData> symbols = extractSymbols(p, unique);
                for (SymbolData symbol : symbols) {
                    out.println(symbol);
                }

                if (p != currentProgram) pman.closeProgram(p, true);
                out.close();
            }

        } else if (merge) {
            DomainFolder folder = askProjectFolder("Select Directory to Symbolify");
            File outFile = askFile("Output file", "OK");
            PrintWriter out = new PrintWriter(new FileWriter(outFile));
            out.println("Module,Location,Name,Mode,Size,Segment");
            List<DomainFile> files_to_symbolify = getAllFilesInDirectory(folder);
            ProgramManager pman = getState().getTool().getService(ProgramManager.class);
            Map<String, List<SymbolData>> symbols = new HashMap<>();
            files_to_symbolify.forEach(f -> {
                Program p = pman.openCachedProgram(f, this);
                symbols.put(p.getName(),extractSymbols(p, unique));
                if (p != currentProgram) pman.closeProgram(p, true);
            });
            symbols.forEach((s,sdList) -> sdList.forEach(sd ->
                    out.printf("\"%s\",%s\n",s,sd.toString())
            ));
            out.close();
        } else {
            File outFile = askFile("Output file", "OK");
            PrintWriter out = new PrintWriter(new FileWriter(outFile));
            out.println("Location,Name,Mode,Size,Segment");
            List<SymbolData> symbols = extractSymbols(currentProgram, unique);
            symbols.stream().sorted().forEach(out::println);
            out.close();
        }

        println("Done!");
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
            Address addr = symbol.getAddress();
            boolean hasExternalRef = Arrays.stream(rm.getReferencesFrom(addr))
                    .anyMatch(Reference::isExternalReference);
            if (hasExternalRef) continue;
            String name = symbol.getName(true);
            String mode = null;
            CodeUnit cu = program.getListing().getCodeUnitAt(addr);
            Function f = fm.getFunctionAt(addr);
            long size = 0;
            if (cu instanceof Instruction) {
                if (f == null) continue;
                if (unique && f.isThunk() && !f.getName()
                        .contains(f.getSymbol().getAddress().toString()))
                    name += "_" + addr;
                var rv = program.getProgramContext().getRegisterValue(tmode, addr);
                if (rv != null) {
                    BigInteger val = rv.getUnsignedValue();
                    mode = Objects.equals(val, BigInteger.ONE) ? "$t" : "$a";
                }
                // Bad news; numAddresses is unreliable if there are multiple ranges.
                if (f.getBody().getNumAddressRanges() == 1) {
                    size = f.getBody().getNumAddresses();
                } else {
                    // This is an okay alternative, though imperfect
                    AddressRangeIterator rangeIter = f.getBody().getAddressRanges();
                    List<AddressRange> ranges = StreamSupport
                            .stream(Spliterators
                            .spliteratorUnknownSize(rangeIter, 0), false)
                            .sorted()
                            .toList();
                    for (AddressRange range : ranges) {
                        // Generate multiple symbols
                        Address ranged_addr = range.getMinAddress();
                        long ranged_size = range.getLength();
                        String ranged_name = name;
                        if (!ranged_addr.equals(addr)) {
                            ranged_name += "_" + ranged_addr;
                        }
                        MemoryBlock segment = getMemoryBlock(ranged_addr);
                        String segName = ".text";
                        if (segment != null) {
                            segName = segment.getName();
                        } else {
                            printf("No block at address %s - The output of " +
                                    "this symbol (%s) will likely be incorrect, as it was set " +
                                    "to .text by default!\n", addr, symbol.getName());
                        }
                        symbolCounts.computeIfAbsent(ranged_name, k -> new ArrayList<>())
                                .add(new SymbolData(ranged_addr, ranged_name, mode, ranged_size, segName));
                    }
                    continue;
                }
            } else if (cu instanceof Data) {
                var d = program.getListing().getDataAt(addr);
                if (d == null) continue;
                size = d.getDataType().getLength();
                mode = "$d";
            }
            if (mode == null || size <= 0) continue;
            MemoryBlock segment = getMemoryBlock(addr);
            String segName = ".text";
            if (segment != null) {
                segName = segment.getName();
            } else {
                printf("No block at address %s - The output of " +
                        "this symbol (%s) will likely be incorrect, as it was set " +
                        "to .text by default!\n", addr, symbol.getName());
            }
            symbolCounts.computeIfAbsent(name, k -> new ArrayList<>())
                    .add(new SymbolData(addr, name, mode, size, segName));
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
        }
        symbols.sort(SymbolData::compareTo);
        return symbols;
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
