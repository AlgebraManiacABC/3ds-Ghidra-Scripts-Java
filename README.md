# 3DS Ghidra Scripts (Java)

A collection of scripts which greatly assist in decompiling 3DS games
(particularly those with relocatable modules).

## Current Scripts
* [MoveStatic](MoveStatic.java) - Moves the `.code` binary to `0x100000` in memory,
and splits it into is respective segments, according to `romfs/static.crs`
* [CROLink](CROLink.java) - The present *chef d'œuvre* of this repository.
Links `.code` to its imported modules (`.cro` files) and each module to each other,
and additionally labels and demangles found symbols.
* [LabelSVCFunctions](LabelSVCFunctions.java) - Labels and bookmarks 
Software Interrupts ([Services / SVC](https://www.3dbrew.org/wiki/SVC))
* LabelServiceHandles (Coming Soon) - Labels handles to services
([Services API](https://www.3dbrew.org/wiki/Services_API))
