package util;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Demangler {
    public static void DemangleAndNameNamespace(Program program, Address addr,
                                TaskMonitor monitor, boolean makePrimary, boolean convertToClass) throws Exception {
        Symbol[] symbols = program.getSymbolTable().getSymbols(addr);
        for (Symbol symbol : symbols) {
            List<DemangledObject> objs = DemanglerUtil.demangle(
                    program, symbol.getName(), addr
            );
            for (var obj : objs) {
                if (apply(program, addr, symbol, obj, monitor, makePrimary, convertToClass)) break;
            }
        }
    }

    private static boolean apply(Program program, Address addr, Symbol mangledSym, DemangledObject obj,
                                 TaskMonitor monitor, boolean makePrimary, boolean convertToClass) throws Exception {

        Namespace ns = resolveNamespace(program, obj);
        String name = obj.getDemangledName();
        if (name == null || name.isBlank()) return false;


        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (convertToClass && ns != null && !ns.isGlobal()) {
            ns = (ns instanceof GhidraClass gc)
                    ? gc
                    : program.getSymbolTable().convertNamespaceToClass(ns);
        }

        if (!makePrimary) {
            SymbolTable symTab = program.getSymbolTable();

            // At a function entry point the function symbol always holds primacy, so
            // setPrimary() on a plain label there does nothing. Move the mangled name
            // onto the function itself first (the old function name comes back below as
            // a label, since the demangled name is what it will have been).
            Symbol funcSym = (func == null) ? null : func.getSymbol();
            if (funcSym != null && !funcSym.equals(mangledSym)) {
                String mangledName = mangledSym.getName();
                Namespace mangledNs = mangledSym.getParentNamespace();
                SourceType source = mangledSym.getSource();
                if (source == SourceType.DEFAULT) source = SourceType.USER_DEFINED;
                symTab.removeSymbolSpecial(mangledSym);
                funcSym.setNameAndNamespace(mangledName, mangledNs, source);
                mangledSym = funcSym;
            }

            // Add alongside the mangled symbol, then make sure it stayed on top.
            symTab.createLabel(addr, name,
                    ns == null ? program.getGlobalNamespace() : ns,
                    SourceType.ANALYSIS);
            mangledSym.setPrimary();
            return true;
        }

        if (!obj.applyTo(program, addr, new DemanglerOptions(), monitor)) return false;
        program.getSymbolTable().removeSymbolSpecial(mangledSym);

        if (func != null) {
            func.setName(name, SourceType.ANALYSIS);
        }
        return true;
    }

    public static Namespace resolveNamespace(Program program, DemangledObject obj)
            throws Exception {
        String full = obj.getNamespaceString();
        if (full == null) return null;
        String[] parts = full.split("::");
        if (parts.length <= 1) return null;

        SymbolTable st = program.getSymbolTable();
        Namespace ns = program.getGlobalNamespace();
        for (int i = 0; i < parts.length - 1; i++) {   // drop the object's own name
            String part = parts[i];
            Namespace child = st.getNamespace(part, ns);
            if (child == null) {
                child = st.createNameSpace(ns, part, SourceType.ANALYSIS);
            } else if (child.getSymbol().getProgram() != program) {
                return null;   // foreign — don't hand it to createLabel
            }
            ns = child;
        }
        return ns;
    }
}
