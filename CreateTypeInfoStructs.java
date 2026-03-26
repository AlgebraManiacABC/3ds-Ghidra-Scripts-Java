// CreateTypeInfoStructs.java
// Ghidra Script: Creates __cxxabiv1 RTTI structs if they do not already exist.
//
// Creates the following in /abi/__cxxabiv1:
//   - __base_class_type_info (used inside __vmi_class_type_info arrays)
//   - __class_type_info      (leaf classes, no bases)
//   - __si_class_type_info   (single, public, non-virtual inheritance)
//   - __vmi_class_type_info  (1 base)
//   - __vmi_class_type_info  (2 bases)
//   - __vmi_class_type_info  (3 bases)
//
// These match the Itanium C++ ABI as used by ARMCC 4.1.
// All pointer fields use the program's default pointer size.
//
// @category RTTI
// @author Claude (for AlgebraManiacABC)

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;

public class CreateTypeInfoStructs extends GhidraScript {

    private DataTypeManager dtm;

    @Override
    public void run() throws Exception {
        dtm = currentProgram.getDataTypeManager();

        int txId = dtm.startTransaction("Create __cxxabiv1 typeinfo structs");
        try {
            createBaseClassTypeInfo();
            createClassTypeInfo();
            createSiClassTypeInfo();
            createVmiClassTypeInfo(1);
            createVmiClassTypeInfo(2);
            createVmiClassTypeInfo(3);
            println("Done. All __cxxabiv1 typeinfo structs created or already present.");
        } finally {
            dtm.endTransaction(txId, true);
        }
    }

    /**
     * Returns the category path /type_info.
     */
    private CategoryPath getCategoryPath() {
        return new CategoryPath("/type_info");
    }

    /**
     * Checks whether a struct with the given name already exists under the category.
     * If it does, prints a message and returns true.
     */
    private boolean alreadyExists(String name) {
        DataType existing = dtm.getDataType(getCategoryPath(), name);
        if (existing != null) {
            println("  SKIP: " + name + " already exists.");
            return true;
        }
        return false;
    }

    /**
     * Resolves a struct into the DTM (adds or returns existing equivalent).
     */
    private DataType resolve(StructureDataType s) {
        DataType resolved = dtm.resolve(s, DataTypeConflictHandler.REPLACE_HANDLER);
        println("  OK:   " + s.getName());
        return resolved;
    }

    /**
     * Returns a pointer type using the program's default pointer size.
     */
    private PointerDataType ptr(DataType dt) {
        return new PointerDataType(dt, currentProgram.getDefaultPointerSize());
    }

    // -----------------------------------------------------------------
    //  __base_class_type_info
    //
    //  struct __base_class_type_info {
    //      const __class_type_info *__base_type;
    //      long __offset_flags;
    //  };
    // -----------------------------------------------------------------
    private void createBaseClassTypeInfo() {
        String name = "__base_class_type_info";
        if (alreadyExists(name)) return;

        // Forward-reference: __class_type_info may not exist yet.
        // Use a void* for the pointer target; user can refine later.
        StructureDataType s = new StructureDataType(getCategoryPath(), name, 0);
        s.add(ptr(DataType.VOID), "__base_type", "const __class_type_info *");
        s.add(LongDataType.dataType, "__offset_flags", "offset and info bitfield");
        resolve(s);
    }

    // -----------------------------------------------------------------
    //  __class_type_info  (no bases)
    //
    //  struct __class_type_info {
    //      void *__vtable_ptr;
    //      const char *__name;
    //  };
    // -----------------------------------------------------------------
    private void createClassTypeInfo() {
        String name = "__class_type_info";
        if (alreadyExists(name)) return;

        StructureDataType s = new StructureDataType(getCategoryPath(), name, 0);
        s.add(ptr(DataType.VOID), "__vtable_ptr", "typeinfo vtable pointer");
        s.add(ptr(CharDataType.dataType), "__name", "mangled name");
        resolve(s);
    }

    // -----------------------------------------------------------------
    //  __si_class_type_info  (single non-virtual public base)
    //
    //  struct __si_class_type_info {
    //      void *__vtable_ptr;
    //      const char *__name;
    //      const __class_type_info *__base_type;
    //  };
    // -----------------------------------------------------------------
    private void createSiClassTypeInfo() {
        String name = "__si_class_type_info";
        if (alreadyExists(name)) return;

        StructureDataType s = new StructureDataType(getCategoryPath(), name, 0);
        s.add(ptr(DataType.VOID), "__vtable_ptr", "typeinfo vtable pointer");
        s.add(ptr(CharDataType.dataType), "__name", "mangled name");
        s.add(ptr(DataType.VOID), "__base_type", "const __class_type_info *");
        resolve(s);
    }

    // -----------------------------------------------------------------
    //  __vmi_class_type_info  (N bases)
    //
    //  struct __vmi_class_type_info {
    //      void *__vtable_ptr;
    //      const char *__name;
    //      unsigned int __flags;
    //      unsigned int __base_count;
    //      __base_class_type_info __base_info[N];
    //  };
    // -----------------------------------------------------------------
    private void createVmiClassTypeInfo(int baseCount) {
        String name = "__vmi_class_type_info_" + baseCount;
        if (alreadyExists(name)) return;

        // Look up __base_class_type_info (should exist by now)
        DataType baseClassTI = dtm.getDataType(getCategoryPath(), "__base_class_type_info");
        if (baseClassTI == null) {
            printerr("ERROR: __base_class_type_info not found. Cannot create " + name);
            return;
        }

        StructureDataType s = new StructureDataType(getCategoryPath(), name, 0);
        s.add(ptr(DataType.VOID), "__vtable_ptr", "typeinfo vtable pointer");
        s.add(ptr(CharDataType.dataType), "__name", "mangled name");
        s.add(UnsignedIntegerDataType.dataType, "__flags", "diamond / non-diamond flags");
        s.add(UnsignedIntegerDataType.dataType, "__base_count", "number of direct bases");

        ArrayDataType baseArray = new ArrayDataType(baseClassTI, baseCount, baseClassTI.getLength());
        s.add(baseArray, "__base_info", "__base_class_type_info[" + baseCount + "]");

        resolve(s);
    }
}