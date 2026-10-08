package org.algebramaniacabc.ctr;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class CXILoader extends AbstractProgramWrapperLoader {

    @Override
    public final String getName() {
        return "CXI Loader and Linker";
    }

    @Override
    public final Collection<LoadSpec> findSupportedLoadSpecs(final ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        // Examine the bytes in 'provider' to determine if this loader can load it.  If it
        // can load it, return the appropriate load specifications.

        return loadSpecs;
    }

    @Override
    protected void load(final Program prgram, final ImporterSettings settiings)
            throws CancelledException, IOException {

        // Load the bytes from 'settings.provider()' into the 'program'.
    }

    @Override
    public final List<Option> getDefaultOptions(final ByteProvider provider, final LoadSpec loadSpec,
                                          final DomainObject domainObject, final boolean isLoadIntoProgram, final boolean mirrorFsLayout) {
        List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject,
                isLoadIntoProgram, mirrorFsLayout);

        // If this loader has custom options, add them to 'list'
        list.add(new Option("Option name goes here", "Default option value goes here"));

        return list;
    }

    @Override
    public String validateOptions(final ByteProvider provider, final LoadSpec loadSpec, final List<Option> options,
                                  final Program program) {

        // If this loader has custom options, validate them here.  Not all options require
        // validation.

        return super.validateOptions(provider, loadSpec, options, program);
    }
}
