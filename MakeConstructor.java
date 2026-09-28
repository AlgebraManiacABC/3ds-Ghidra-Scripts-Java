// Turns the function under the cursor into a constructor of a given class: it is moved
// into the class namespace and given both spellings of the constructor's name -- the
// demangled one (Foo::Foo) on the function itself, and the Itanium mangled one
// (_ZN3FooC1Ev) alongside it as a label.
//
// The function symbol always holds primacy at an entry point, so naming the function
// with the demangled spelling is what makes it primary; ToggleMangledNames can swap
// the two afterwards (ExportSymbols wants the mangled one on top).
//
// Parameters are not mangled -- like the vtable naming in RenameVTableFunctions, the
// mangled spelling always says "void". If the constructor takes arguments the label is
// still added, with a warning, since the demangled name is the one being read.
//
//@category 3DS
//@author Claude (for AlgebraManiacABC)

import ghidra.app.script.GhidraScript;
import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import util.RenameVTableFunctions;

import java.util.List;

public class MakeConstructor extends GhidraScript {

    private static final SourceType SOURCE = SourceType.USER_DEFINED;

    // The Itanium structor codes, as the choice list shows them.
    private static final String C1 = "C1: complete object constructor";
    private static final String C2 = "C2: base object constructor";
    private static final String C3 = "C3: allocating constructor";

    @Override
    protected void run() throws Exception {
        if (currentAddress == null) {
            println("No current address; put the cursor in a function first.");
            return;
        }
        Function func = getFunctionContaining(currentAddress);
        if (func == null) {
            printf("No function at %s.\n", currentAddress);
            return;
        }
        if (func.isThunk()) {
            println("That is a thunk; name the function it forwards to instead.");
            return;
        }

        String path = askString("Make Constructor",
                "Class for the constructor at " + func.getEntryPoint()
                        + " (A::B for a nested class):", defaultClassPath(func));
        if (path == null || path.isBlank()) {
            println("No class given.");
            return;
        }

        GhidraClass cls = resolveClass(path.trim());
        String variant = askChoice("Constructor variant",
                "Which constructor is this?", List.of(C1, C2, C3), C1)
                .substring(0, 2);

        String mangled = RenameVTableFunctions.mangle(cls, variant);
        if (mangled == null) {
            printf("Cannot spell a mangled name for %s; nothing changed.\n",
                    cls.getName(true));
            return;
        }

        Address addr = func.getEntryPoint();
        SymbolTable symTab = currentProgram.getSymbolTable();
        String demangled = cls.getName();

        // A label already sitting here under the name the function is about to take
        // would collide with it -- two symbols at one address cannot share a name
        // within the same namespace.
        for (Symbol sym : symTab.getSymbols(addr)) {
            if (sym.equals(func.getSymbol())) continue;
            if (sym.getName().equals(demangled) && sym.getParentNamespace().equals(cls)) {
                symTab.removeSymbolSpecial(sym);
            }
        }

        func.getSymbol().setNameAndNamespace(demangled, cls, SOURCE);

        if (labelHere(addr, mangled)) {
            printf("%s is now %s::%s, and already carried %s.\n",
                    addr, cls.getName(true), demangled, mangled);
        } else {
            symTab.createLabel(addr, mangled, currentProgram.getGlobalNamespace(), SOURCE);
            printf("%s is now %s::%s, mangled as %s.\n",
                    addr, cls.getName(true), demangled, mangled);
        }

        int explicit = explicitParameters(func);
        if (explicit > 0) {
            printf("    NOTE: the mangled name spells no parameters, but this function"
                    + " has %d.\n", explicit);
        }
    }

    /** The class path to offer: whatever namespace the function is in already. */
    private String defaultClassPath(Function func) {
        Namespace ns = func.getParentNamespace();
        return (ns == null || ns.isGlobal()) ? "" : ns.getName(true);
    }

    /** Resolve (creating as needed) the namespace path, with its leaf made a class. */
    private GhidraClass resolveClass(String path) throws Exception {
        if (path.startsWith("Global::")) path = path.substring("Global::".length());
        Namespace ns = NamespaceUtils.createNamespaceHierarchy(path,
                currentProgram.getGlobalNamespace(), currentProgram, SOURCE);
        if (ns instanceof GhidraClass gc) return gc;
        return currentProgram.getSymbolTable().convertNamespaceToClass(ns);
    }

    private boolean labelHere(Address addr, String name) {
        for (Symbol sym : currentProgram.getSymbolTable().getSymbols(addr)) {
            if (sym.getName().equals(name)) return true;
        }
        return false;
    }

    /** Parameters the function really declares, i.e. not the "this" Ghidra adds itself. */
    private int explicitParameters(Function func) {
        int count = 0;
        for (Parameter param : func.getParameters()) {
            if (!param.isAutoParameter()) count++;
        }
        return count;
    }
}
