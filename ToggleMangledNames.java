// Swaps which of an address's names is primary: the mangled one (_Z...) or its
// demangled counterpart.
//
// Both names stay on the address either way; only primacy moves. Export wants the
// mangled name primary (see ExportSymbols), reading the decompiler wants the
// demangled one.
//
// At a function's entry point the function symbol always holds primacy, so a plain
// label there can never be made primary with setPrimary(). For those addresses the
// two names are swapped between the function symbol and the label instead.
//
//@category Tests
//@author AlgebraManiacABC

import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class ToggleMangledNames extends GhidraScript {

    private static final String TOGGLE = "Toggle";
    private static final String MANGLED = "Mangled";
    private static final String DEMANGLED = "Demangled";

    // Default names Ghidra generates; never a demangled counterpart.
    private static final List<String> DEFAULT_PREFIXES = List.of(
            "FUN_", "SUB_", "LAB_", "DAT_", "PTR_", "UNK_", "EXT_", "s_",
            "caseD_", "switchD_", "case", "default");

    private int changed = 0;
    private int alreadySet = 0;
    private int noCounterpart = 0;

    @Override
    protected void run() throws Exception {
        String mode = askChoice("Primary symbol names",
                "Which name should be primary?\n" +
                        TOGGLE + ": flip whatever each address currently has\n" +
                        MANGLED + ": needed for symbol export\n" +
                        DEMANGLED + ": readable in the listing and decompiler",
                List.of(TOGGLE, MANGLED, DEMANGLED), TOGGLE);

        AddressSetView scope = currentSelection;
        if (scope != null && !scope.isEmpty()) {
            println("Operating on the current selection.");
        } else {
            scope = null;
            println("Operating on the whole program.");
        }

        SymbolTable symTab = currentProgram.getSymbolTable();

        // Collect the addresses that carry a mangled name, so each is handled once
        // even when several of its symbols are mangled.
        Set<Address> addrs = new LinkedHashSet<>();
        SymbolIterator iter = symTab.getAllSymbols(false);
        while (iter.hasNext()) {
            monitor.checkCancelled();
            Symbol sym = iter.next();
            if (sym.isExternal() || !isMangled(sym.getName())) continue;
            Address addr = sym.getAddress();
            if (scope != null && !scope.contains(addr)) continue;
            addrs.add(addr);
        }

        monitor.initialize(addrs.size());
        monitor.setMessage("Setting primary symbol names");
        for (Address addr : addrs) {
            monitor.checkCancelled();
            monitor.incrementProgress(1);
            try {
                apply(addr, mode);
            } catch (Exception e) {
                printf("    WARNING: could not set primary name at %s : %s\n",
                        addr, e.getMessage());
            }
        }

        printf("Done! %d changed, %d already correct, %d without a counterpart name.\n",
                changed, alreadySet, noCounterpart);
    }

    private void apply(Address addr, String mode) throws Exception {
        SymbolTable symTab = currentProgram.getSymbolTable();

        Symbol mangled = null;
        Symbol demangled = null;
        for (Symbol sym : symTab.getSymbols(addr)) {
            String name = sym.getName();
            if (isMangled(name)) {
                if (mangled == null || sym.isPrimary()) mangled = sym;
            } else if (!sym.isDynamic() && !isDefaultName(name)) {
                if (demangled == null || sym.isPrimary()) demangled = sym;
            }
        }
        if (mangled == null) return;

        boolean wantMangled = switch (mode) {
            case MANGLED -> true;
            case DEMANGLED -> false;
            default -> !mangled.isPrimary();
        };

        Symbol want = mangled;
        if (!wantMangled) {
            if (demangled == null) {
                demangled = createDemangledLabel(addr, mangled.getName());
            }
            if (demangled == null) {
                noCounterpart++;
                return;
            }
            want = demangled;
        }

        if (want.isPrimary()) {
            alreadySet++;
            return;
        }
        if (makePrimary(addr, want)) changed++;
    }

    /** Make the given symbol the primary one at addr, swapping names if it is a function entry. */
    private boolean makePrimary(Address addr, Symbol want) throws Exception {
        Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            return want.setPrimary();
        }

        Symbol funcSym = func.getSymbol();
        if (funcSym.equals(want)) {
            return want.setPrimary();
        }

        // The function symbol holds primacy here, so move the wanted name onto it and
        // put the name it had back as a label. The label has to go first: two symbols
        // at one address cannot share a name within the same namespace.
        String wantName = want.getName();
        Namespace wantNs = want.getParentNamespace();
        SourceType wantSource = sourceOf(want);
        String oldName = funcSym.getName();
        Namespace oldNs = funcSym.getParentNamespace();
        SourceType oldSource = sourceOf(funcSym);

        SymbolTable symTab = currentProgram.getSymbolTable();
        symTab.removeSymbolSpecial(want);
        funcSym.setNameAndNamespace(wantName, wantNs, wantSource);
        symTab.createLabel(addr, oldName, oldNs, oldSource);
        return true;
    }

    /** Demangle the name and add the result as a label, so there is something to toggle to. */
    private Symbol createDemangledLabel(Address addr, String mangledName) throws Exception {
        for (DemangledObject obj : DemanglerUtil.demangle(currentProgram, mangledName, addr)) {
            String name = obj.getDemangledName();
            if (name == null || name.isBlank()) continue;
            Namespace ns = util.Demangler.resolveNamespace(currentProgram, obj);
            return currentProgram.getSymbolTable().createLabel(addr, name,
                    ns == null ? currentProgram.getGlobalNamespace() : ns,
                    SourceType.ANALYSIS);
        }
        return null;
    }

    private SourceType sourceOf(Symbol sym) {
        // DEFAULT is not a legal source for an explicit rename.
        SourceType source = sym.getSource();
        return source == SourceType.DEFAULT ? SourceType.USER_DEFINED : source;
    }

    private boolean isMangled(String name) {
        return name != null && (name.startsWith("_Z") || name.startsWith("__Z"));
    }

    private boolean isDefaultName(String name) {
        for (String prefix : DEFAULT_PREFIXES) {
            if (name.startsWith(prefix)) return true;
        }
        return false;
    }
}
