# 3DS Ghidra Scripts (Java)

A collection of scripts which greatly assist in decompiling 3DS games (particularly those with relocatable modules).

## Current Scripts
* [ImportStaticCRS](ImportStaticCRS.java) - The present *chef d'œuvre* of this repository. Links .code/code.bin to its imported modules (.cro files), but also sets up the memory regions, acquires named exports, and calls the demangler.
* CROLink (Coming Soon) - a WIP rewrite of ImportStaticCRS which will handle all crx files and link them automagically!
* [LabelSVCFunctions](LabelSVCFunctions.java) - Labels and bookmarks Software Interrupts ([Services / SVC](https://www.3dbrew.org/wiki/SVC))
* LabelServiceHandles (Coming Soon) - Labels handles to services ([Services API](https://www.3dbrew.org/wiki/Services_API))
