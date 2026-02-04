# 3DS Ghidra Scripts (Java)

A collection of scripts which greatly assist in decompiling 3DS games
(particularly those with relocatable modules).

## Current Scripts
* [MoveStatic](MoveStatic.java) - Moves the `.code` binary to `0x100000` in memory,
and splits it into is respective segments, according to `romfs/static.crs`
* [CROLink](CROLink.java) - The present *chef d'œuvre* of this repository.
Links `.code` to its imported modules (`.cro` files) and each module to each other,
and additionally labels and demangles found symbols.
* [SplitToELF](SplitToELF.java) - A close second to CROLink in terms of utility.
Accepts a directory of compiled objects (`.o`), and splits the current Ghidra
program into its own `.o` files, outputting them into another directory for
linkage with your favorite linker (mine is the
[devkitARM](https://devkitpro.org/wiki/Getting_Started) `arm-none-aebi-ld`).
Just make sure the order is known ahead of time.
* [LabelSVCFunctions](LabelSVCFunctions.java) - Labels and bookmarks 
Software Interrupts ([Services / SVC](https://www.3dbrew.org/wiki/SVC))
* LabelServiceHandles (Coming Soon) - Labels handles to services
([Services API](https://www.3dbrew.org/wiki/Services_API))

## Credit

* [zaksabeast](https://github.com/zaksabeast) for your [Python scripts](https://github.com/zaksabeast/3ds-Ghidra-Scripts) as inspiration as the basis of LabelSVCFunctions/LabelServiceHandles
* The [Reverse Engineering Discord](https://discord.gg/Pd4yAzV7ye) and the [Ghidra docs](https://ghidra.re/ghidra_docs/api/index.html) for Ghidra API help
* [CRO0](https://www.3dbrew.org/wiki/CRO0) on 3dbrew
* [wwylele](https://gist.github.com/wwylele)'s [CRO doc](https://gist.github.com/wwylele/325d53ee6a0f1dff6aa3473377335d93)
* Lots of work in the [3DS Decomp Server](https://discord.gg/dFgw7CwrEX)!
