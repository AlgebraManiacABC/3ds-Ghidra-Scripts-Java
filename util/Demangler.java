package util;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;

import java.util.Arrays;
import java.util.List;

public class Demangler {
    public static void DemangleAndNameNamespace(Program program, Address addr,
                                TaskMonitor monitor) throws Exception {
        Symbol[] symbols = program.getSymbolTable().getSymbols(addr);
        for (Symbol symbol : symbols) {
            List<DemangledObject> objs = DemanglerUtil.demangle(
                    program, symbol.getName(), addr
            );
            for (var obj : objs) {
                boolean applied = obj.applyTo(program, addr,
                        new DemanglerOptions(), monitor);
                if (applied) {
                    program.getSymbolTable().removeSymbolSpecial(symbol);
                    String fullName = obj.getNamespaceString();
                    String[] namespaceParts = fullName.split("::");
                    String[] namespace = null;
                    if (namespaceParts.length > 1) {
                        namespace = Arrays.copyOfRange(
                                namespaceParts,0,namespaceParts.length-1);
                    }
                    Function func = program.getFunctionManager()
                            .getFunctionAt(addr);
                    if (func != null) {
                        func.setName(obj.getDemangledName(),
                                SourceType.ANALYSIS);
                        if (namespace != null) {
                            Namespace ns = NamespaceUtils
                                    .createNamespaceHierarchy(
                                        String.join("::",namespace),
                                        null,  // parent (null = global)
                                        program,
                                        SourceType.ANALYSIS
                            );
                            func.setParentNamespace(ns);
                        }
                    }
                    break;
                }
            }
        }
    }
}
