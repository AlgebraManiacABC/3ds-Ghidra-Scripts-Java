//@category 3DS

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Reports symbol names that are defined at more than one address, along with every
 * address that carries the name. Only primary symbols are considered. Names are
 * compared fully qualified, so A::foo and B::foo are not considered duplicates
 * of each other.
 */
public class ReportDuplicateSymbols extends GhidraScript {

    @Override
    protected void run() throws Exception {
        SymbolTable symTab = currentProgram.getSymbolTable();

        Map<String, List<Symbol>> byName = new TreeMap<>();
        int scanned = 0;

        SymbolIterator it = symTab.getSymbolIterator(true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Symbol sym = it.next();

            if (!sym.isPrimary()) continue;
            if (sym.isDynamic()) continue;
            if (sym.isExternal()) continue;
            SymbolType type = sym.getSymbolType();
            if (type == SymbolType.PARAMETER || type == SymbolType.LOCAL_VAR) continue;

            scanned++;
            byName.computeIfAbsent(sym.getName(true), k -> new ArrayList<>()).add(sym);
        }

        // Only one primary symbol exists per address, so any name seen twice is a duplicate.
        Map<String, List<Symbol>> dups = new LinkedHashMap<>();
        for (Map.Entry<String, List<Symbol>> e : byName.entrySet()) {
            List<Symbol> syms = e.getValue();
            if (syms.size() < 2) continue;
            syms.sort(Comparator.comparing(Symbol::getAddress));
            dups.put(e.getKey(), syms);
        }

        if (dups.isEmpty()) {
            println("No duplicate symbol names among " + scanned + " primary symbols.");
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append(dups.size()).append(" duplicated symbol name(s) out of ")
          .append(scanned).append(" primary symbols:\n");
        for (Map.Entry<String, List<Symbol>> e : dups.entrySet()) {
            sb.append(e.getKey()).append(" (").append(e.getValue().size()).append("):\n");
            for (Symbol sym : e.getValue()) {
                sb.append("\t").append(sym.getAddress())
                  .append("\t").append(sym.getSymbolType())
                  .append("\n");
            }
        }
        println(sb.toString());
    }
}
