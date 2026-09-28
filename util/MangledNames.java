// Itanium spellings for the RTTI data symbols: _ZTV for a vtable, _ZTI for a typeinfo
// struct. Wherever the pipeline writes a truthful demangled label ("vtable", "typeinfo"),
// it writes the mangled one beside it, the same way emitMangledName does for functions.
//
// @category RTTI
// @author Claude (for AlgebraManiacABC)

package util;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public final class MangledNames {

    private static final int PTR_SIZE = 4;

    private MangledNames() {}

    /**
     * The Itanium {@code <name>} production for a class -- what follows _ZTV, _ZTI or
     * _ZTS -- read off the _ZTS symbol already sitting on the class's name string.
     * This is the compiler's own spelling, so templates and operators, which
     * {@link RenameVTableFunctions#mangleTypeName} cannot re-spell, come out right.
     */
    public static String typeNameFromNameString(Program program, Address nameStrAddr) {
        if (nameStrAddr == null) return null;
        for (Symbol sym : program.getSymbolTable().getSymbols(nameStrAddr)) {
            String name = sym.getName();
            if (name.startsWith("_ZTS") && name.length() > 4) return name.substring(4);
        }
        return null;
    }

    /** The same encoding, reached through a typeinfo struct's __name pointer. */
    public static String typeNameFromTypeinfo(Program program, Address typeinfoAddr) {
        if (typeinfoAddr == null) return null;
        try {
            long namePtr = Integer.toUnsignedLong(
                    program.getMemory().getInt(typeinfoAddr.add(PTR_SIZE)));
            return typeNameFromNameString(program, typeinfoAddr.getNewAddress(namePtr));
        } catch (Exception e) {
            // Unreadable __name: the caller falls back to spelling the namespace itself
            return null;
        }
    }

    /**
     * The encoding for a class namespace: its own typeinfo's _ZTS string when there is
     * one, otherwise the namespace spelled out. Null when neither can be had.
     */
    public static String typeNameForClass(Program program, Namespace ns) {
        if (ns == null || ns.isGlobal()) return null;
        Address typeinfoAddr = null;
        for (Symbol sym : program.getSymbolTable().getSymbols("typeinfo", ns)) {
            typeinfoAddr = sym.getAddress();
            break;
        }
        String enc = typeNameFromTypeinfo(program, typeinfoAddr);
        return (enc != null) ? enc : RenameVTableFunctions.mangleTypeName(ns);
    }

    /**
     * Add a mangled RTTI name beside the demangled label already at addr, on the contract
     * emitMangledName uses for functions: global namespace, SourceType.ANALYSIS, never
     * primary. An ANALYSIS _ZTV/_ZTI label this pass wrote before is revised; any other
     * _ZT* name is someone's real one -- imported, hand-written, toggled -- and nothing
     * is written at all. True when a label was added.
     */
    public static boolean addMangled(GhidraScript script, Program program,
                                     Address addr, String mangled) {
        if (addr == null || mangled == null) return false;
        SymbolTable symTab = program.getSymbolTable();

        Symbol stale = null;
        for (Symbol sym : symTab.getSymbols(addr)) {
            String name = sym.getName();
            if (!name.startsWith("_ZT")) continue;
            if (name.equals(mangled)) return false;
            if (sym.getSource() != SourceType.ANALYSIS) return false;
            // Every _ZT* spelling this class writes, so a re-run revises its own prior
            // label instead of stacking a second one beside it.
            // _ZT_C<n>_/_ZT_B1_ are ARMCC's construction-vtable forms and are what this
            // pipeline writes -- matched on the _ZT_C/_ZT_B prefix, not on a depth of 1,
            // so a table whose depth changed between runs (C1 -> C2 once the full path was
            // spelled) revises its label instead of keeping both.
            // pipeline writes. Itanium's _ZTC is listed too: a build briefly wrote it, and
            // SafeImportSymbols can import a real one, so a re-run has to recognise it as
            // a name for the same thing rather than leave two on the address.
            if (name.startsWith("_ZTV") || name.startsWith("_ZTI")
                    || name.startsWith("_ZTT") || name.startsWith("_ZTC")
                    || name.startsWith("_ZT_C") || name.startsWith("_ZT_B")) {
                stale = sym;
            }
        }
        if (stale != null) stale.delete();

        try {
            symTab.createLabel(addr, mangled, program.getGlobalNamespace(),
                    SourceType.ANALYSIS);
            return true;
        } catch (Exception e) {
            script.println("    WARNING: could not label " + mangled + " at " + addr);
            return false;
        }
    }
}
