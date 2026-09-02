// SafeImportSymbols.java — a cautious variant of ImportSymbols.java.
//
// Same job, but it refuses to throw away information you already have:
//   * Only symbols which are actually named are imported. Anything the CSV
//     carries as FUN_/DAT_/LAB_/thunk_FUN_/... is noise and is dropped.
//   * A name already in the program is only replaced as far as the one question
//     this script asks allows; otherwise the incoming name is *added* alongside
//     it, as either the new primary or a secondary label.
//   * Function bodies are never resized, and mangled names are left mangled -
//     DemangleThis is the script for that.
//
// Accepts both CSV shapes used in this project:
//   1. ImportSymbols format, no header row:
//        name,address,size,type[,extra]      type = O | m | M | U, extra = gdef
//   2. ExportSymbols format, with its header row:
//        [Module,]Location,Name,Namespace,Mode,Size,Segment
//
//@category 3DS
//@menupath Tools.Safe Import Symbols CSV

import ghidra.app.script.GhidraScript;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolUtilities;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

public class SafeImportSymbols extends GhidraScript {

    // How the incoming name is allowed to treat the name already at the address.
    private static final String OW_UNNAMED   = "Replace unnamed (leave every real name alone)";
    private static final String OW_NEW_FIRST = "Prefer new (add the imported name as primary)";
    private static final String OW_OLD_FIRST = "Prefer old (add the imported name as secondary)";
    private static final String OW_ALL       = "Replace all (the imported name wins outright)";

    private static final SourceType SOURCE = SourceType.IMPORTED;

    /** One CSV row, after both formats have been reduced to the same shape. */
    private record Entry(String name, Address addr, long size, boolean code,
                         String namespace, boolean globalDef) {}

    private int named, addedPrimary, addedSecondary, functionsCreated,
            skippedUnnamed, skippedSame, skippedAddress, skippedProtected,
            skippedModule, errors;

    @Override
    protected void run() throws Exception {

        File csvFile = askFile("Select symbol CSV file", "Import");
        if (csvFile == null) {
            println("No file selected - aborting.");
            return;
        }

        String policy = askChoice("Overwrite strength",
                "An imported name lands on an address which already has a real name. Then what?",
                List.of(OW_UNNAMED, OW_NEW_FIRST, OW_OLD_FIRST, OW_ALL), OW_UNNAMED);

        SymbolTable symTab = currentProgram.getSymbolTable();
        FunctionManager fm = currentProgram.getFunctionManager();
        String module = currentProgram.getName();

        int lineNum = 0;
        try (BufferedReader reader = new BufferedReader(new FileReader(csvFile))) {
            String first = reader.readLine();
            if (first == null) {
                println("Empty file - nothing to import.");
                return;
            }
            lineNum++;

            boolean exportFormat = isExportHeader(first);
            boolean merged = exportFormat && stripQuotes(splitCsv(first).getFirst())
                    .equalsIgnoreCase("Module");

            String line = first;
            if (exportFormat) { // The header isn't data.
                line = reader.readLine();
                lineNum++;
            }
            for (; line != null; line = reader.readLine(), lineNum++) {
                if (monitor.isCancelled()) {
                    println("Cancelled by user at line " + lineNum);
                    break;
                }
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("//")) {
                    continue;
                }

                Entry entry;
                try {
                    entry = exportFormat
                            ? parseExportRow(splitCsv(line), merged, module)
                            : parseImportRow(splitCsv(line));
                } catch (Exception e) {
                    printerr("Line " + lineNum + ": " + e.getMessage() + " - skipping: " + trimmed);
                    errors++;
                    continue;
                }
                if (entry == null) continue; // already counted as skipped

                // The whole point: a name which isn't a name teaches us nothing.
                if (entry.name().isBlank() || isMadeUpName(entry.name())) {
                    skippedUnnamed++;
                    continue;
                }
                if (!currentProgram.getMemory().contains(entry.addr())) {
                    printerr("Line " + lineNum + ": " + entry.addr() + " is not in memory.");
                    skippedAddress++;
                    continue;
                }

                try {
                    importEntry(entry, symTab, fm, policy);
                } catch (Exception e) {
                    printerr("Line " + lineNum + ": could not apply \"" + entry.name()
                            + "\" at " + entry.addr() + " - " + e.getMessage());
                    errors++;
                }
            }
        }

        println("=== Import complete ===");
        println("  Named                : " + named);
        println("  Added as primary     : " + addedPrimary);
        println("  Added as secondary   : " + addedSecondary);
        println("  Functions created    : " + functionsCreated);
        println("  Skipped (unnamed)    : " + skippedUnnamed);
        println("  Skipped (identical)  : " + skippedSame);
        println("  Skipped (bad address): " + skippedAddress);
        println("  Skipped (protected)  : " + skippedProtected);
        if (skippedModule > 0)
            println("  Skipped (other module): " + skippedModule);
        println("  Errors               : " + errors);
        println("  Total lines processed: " + lineNum);
    }

    private void importEntry(Entry entry, SymbolTable symTab, FunctionManager fm, String policy)
            throws Exception {

        Address addr = entry.addr();
        Namespace ns = entry.globalDef()
                ? currentProgram.getGlobalNamespace()
                : resolveNamespace(entry.namespace());

        if (alreadyHere(symTab, addr, entry.name(), ns)) {
            skippedSame++;
            return;
        }

        if (entry.code()) {
            Function func = fm.getFunctionAt(addr);
            if (func == null) {
                // ARM/Thumb CSVs sometimes carry the LSB-set entry address.
                func = fm.getFunctionAt(addr.getNewAddress(addr.getOffset() | 1));
            }
            // Existing bodies are left exactly as they are.
            if (func == null && createFunctionAt(addr, entry.size()) != null) {
                functionsCreated++;
            }
        }

        applyName(symTab, addr, entry.name(), ns, policy);
    }

    /** Puts the name at the address as forcefully as the chosen policy permits. */
    private void applyName(SymbolTable symTab, Address addr, String name, Namespace ns,
                           String policy) throws Exception {

        Symbol existing = symTab.getPrimarySymbol(addr);

        // A dynamic symbol isn't really there, and a FUN_/DAT_ name held by a real
        // one is equally worthless - either way, nothing is lost by taking the spot.
        if (existing == null || existing.isDynamic()) {
            symTab.createLabel(addr, name, ns, SOURCE).setPrimary();
            named++;
            return;
        }
        if (isMadeUpName(existing.getName()) || OW_ALL.equals(policy)) {
            existing.setNameAndNamespace(name, ns, SOURCE);
            named++;
            return;
        }

        switch (policy) {
            case OW_OLD_FIRST -> {
                symTab.createLabel(addr, name, ns, SOURCE);
                addedSecondary++;
            }
            case OW_NEW_FIRST -> {
                Symbol added = symTab.createLabel(addr, name, ns, SOURCE);
                if (added.setPrimary()) {
                    addedPrimary++;
                } else {
                    // A function entry keeps its function symbol primary, so this is a label.
                    printf("Kept \"%s\" primary at %s; \"%s\" added alongside it.\n",
                            existing.getName(), addr, name);
                    addedSecondary++;
                }
            }
            default -> skippedProtected++;
        }
    }

    private Function createFunctionAt(Address addr, long size) {
        try {
            if (size > 0) {
                AddressSet body = new AddressSet(addr, addr.add(size - 1));
                // Named later, under the overwrite policy.
                return currentProgram.getFunctionManager()
                        .createFunction(null, addr, body, SOURCE);
            }
            return createFunction(addr, null);
        } catch (Exception e) {
            println("Could not create a function at " + addr + " - " + e.getMessage());
            errors++;
            return null;
        }
    }

    // ------------------------------------------------------------------ parsing

    private Entry parseImportRow(List<String> parts) {
        if (parts.size() < 4) {
            throw new IllegalArgumentException("expected at least 4 fields, got " + parts.size());
        }
        String name = parts.get(0).trim();
        Address addr = resolveAddress(parts.get(1));
        if (addr == null) {
            throw new IllegalArgumentException("bad address '" + parts.get(1).trim() + "'");
        }
        long size;
        try {
            size = Long.parseLong(parts.get(2).trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("bad size '" + parts.get(2).trim() + "'");
        }
        String type = parts.get(3).trim();
        boolean globalDef = false;
        for (int i = 4; i < parts.size(); i++) {
            if ("gdef".equalsIgnoreCase(parts.get(i).trim())) globalDef = true;
        }
        return new Entry(name, addr, size, !"U".equalsIgnoreCase(type), null, globalDef);
    }

    private Entry parseExportRow(List<String> fields, boolean merged, String module) {
        if (merged) {
            if (fields.isEmpty()) return null;
            String rowModule = fields.getFirst();
            // A merged export carries every module; only ours belongs in this program.
            if (!rowModule.equals(module) && !stripExt(rowModule).equals(stripExt(module))) {
                skippedModule++;
                return null;
            }
            fields = fields.subList(1, fields.size());
        }
        if (fields.size() < 5) {
            throw new IllegalArgumentException("expected at least 5 fields, got " + fields.size());
        }
        Address addr = resolveAddress(fields.get(0));
        if (addr == null) {
            throw new IllegalArgumentException("bad address '" + fields.get(0).trim() + "'");
        }
        String name = fields.get(1).trim();
        String namespace = fields.get(2).trim();
        String mode = fields.get(3).trim();
        long size = 0;
        try {
            size = Long.parseLong(fields.get(4).trim(), 16);
        } catch (NumberFormatException ignored) {
            // Size is a nicety here; the name is what we came for.
        }
        return new Entry(name, addr, size, !"$d".equals(mode), namespace, false);
    }

    private boolean isExportHeader(String line) {
        String first = stripQuotes(splitCsv(line).getFirst());
        return first.equalsIgnoreCase("Module") || first.equalsIgnoreCase("Location");
    }

    private Address resolveAddress(String text) {
        String s = stripQuotes(text.trim());
        try {
            Address addr = currentProgram.getAddressFactory().getAddress(s);
            if (addr != null) return addr;
        } catch (Exception ignored) {
        }
        try {
            return currentProgram.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(Long.parseLong(s, 16));
        } catch (Exception e) {
            return null;
        }
    }

    // ------------------------------------------------------------------ helpers

    private boolean alreadyHere(SymbolTable symTab, Address addr, String name, Namespace ns) {
        for (Symbol s : symTab.getSymbols(addr)) {
            if (s.getName().equals(name) && s.getParentNamespace().equals(ns)) return true;
        }
        return false;
    }

    private Namespace resolveNamespace(String namespace) throws Exception {
        Namespace global = currentProgram.getGlobalNamespace();
        if (namespace == null) return global;
        String path = namespace.trim();
        if (path.isEmpty() || path.equals("Global")) return global;
        if (path.startsWith("Global::")) path = path.substring("Global::".length());
        if (path.isEmpty()) return global;
        return NamespaceUtils.createNamespaceHierarchy(path, global, currentProgram, SOURCE);
    }

    /**
     * True for the names Ghidra invents for us - the ones which carry no information,
     * and so are neither worth importing nor worth protecting.
     */
    private boolean isMadeUpName(String name) {
        if (SymbolUtilities.isReservedDynamicLabelName(name, currentProgram.getAddressFactory()))
            return true;
        String bare = name.startsWith("thunk_") ? name.substring("thunk_".length()) : name;
        for (String prefix : List.of("FUN_", "DAT_", "LAB_", "SUB_", "UNK_", "EXT_",
                "OFF_", "PTR_", "ARRAY_", "caseD_", "switchD_", "switchdataD_", "s_", "u_")) {
            if (bare.startsWith(prefix)) return true;
        }
        return false;
    }

    private String stripExt(String name) {
        int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot) : name;
    }

    private String stripQuotes(String s) {
        String t = s.trim();
        if (t.length() >= 2 && t.startsWith("\"") && t.endsWith("\"")) {
            return t.substring(1, t.length() - 1);
        }
        return t;
    }

    // ExportSymbols quotes every field but the mode, and names can hold commas (templates).
    private List<String> splitCsv(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (quoted && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    field.append('"');
                    i++;
                } else {
                    quoted = !quoted;
                }
            } else if (c == ',' && !quoted) {
                fields.add(field.toString());
                field.setLength(0);
            } else {
                field.append(c);
            }
        }
        fields.add(field.toString());
        return fields;
    }
}
