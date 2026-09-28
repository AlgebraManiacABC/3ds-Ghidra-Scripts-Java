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
import ghidra.program.model.mem.Memory;
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

    /**
     * The class a typeinfo describes, read from its {@code _ZTS} string rather than from
     * any symbol.
     *
     * <p>A typeinfo's second word points at its mangled type name, which is in the bytes
     * whether or not anything has labelled it. Looking the class up through a
     * {@code typeinfo} label instead made cross-module resolution depend on a CRO having
     * been through the RTTI pipeline <em>and saved</em>: on a clean project every base
     * living in a CRO came back unresolved and its derived classes looked rootless.
     *
     * @return the qualified class name, spelled the way the RTTI pipeline names the
     *         class's namespace, or null when the word does not lead to a mangled type name
     */
    public static String classNameOfTypeinfo(Program program, Address typeinfo) {
        try {
            Memory mem = program.getMemory();
            long namePtr = Integer.toUnsignedLong(mem.getInt(typeinfo.add(4)));
            Address nameAddr = typeinfo.getNewAddress(namePtr);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 512; i++) {
                int c = mem.getByte(nameAddr.add(i)) & 0xff;
                if (c == 0) break;
                boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                        || (c >= '0' && c <= '9') || c == '_' || c == '$' || c == '.';
                if (!ok) return null;
                sb.append((char) c);
            }
            if (sb.length() == 0) return null;
            for (DemangledObject obj : DemanglerUtil.demangle(program, "_ZTS" + sb, nameAddr)) {
                String full = obj.getNamespaceString();
                if (full == null || full.isBlank()) continue;
                // getNamespaceString() ends in the object's own name ("typeinfo-name"),
                // which resolveNamespace drops too; what precedes it is the class. Strip it
                // by name rather than at the last "::", so a template argument that is
                // itself qualified stays whole.
                String own = obj.getName();
                if (own != null && !own.isEmpty() && full.endsWith("::" + own)) {
                    return full.substring(0, full.length() - own.length() - 2);
                }
                if (own == null || !full.equals(own)) return full;
            }
        } catch (Exception e) {
            // Unreadable or not a type name.
        }
        return null;
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
