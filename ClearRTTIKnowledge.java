//@category RTTI

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;

public class ClearRTTIKnowledge extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Options opts = currentProgram.getOptions("RTTI_CHOICES");
        for (String name : opts.getOptionNames()) {
            opts.removeOption(name);
        }
    }
}
