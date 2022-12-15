# decomp-toolkit [![Build Status]][actions]

[Build Status]: https://github.com/encounter/decomp-toolkit/actions/workflows/build.yml/badge.svg
[actions]: https://github.com/encounter/decomp-toolkit/actions

GameCube/Wii decompilation project tools.

This provides various commands that assist with creating a build system that works
across all major platforms without dealing with platform-specific C compilers,
UNIX compatibility layers like msys2, or other idiosyncrasies.

## Commands

### ar create

Create a static library (.a) from the input objects.

```shell
$ dtk ar create out.a input_1.o input_2.o
# or
$ echo input_1.o >> rspfile
$ echo input_2.o >> rspfile
$ dtk ar create out.a @rspfile
```

### demangle

Demangles CodeWarrior C++ symbols. A thin wrapper for [cwdemangle](https://github.com/encounter/cwdemangle).

```shell
$ dtk demangle 'BuildLight__9CGuiLightCFv'
CGuiLight::BuildLight() const
```

### elf disasm

Disassemble an unstripped CodeWarrior ELF file into fully-split & fully-shiftable assembly files.

```shell
$ dtk disasm input.elf out
```

### elf fixup

Fixes issues with GNU assembler-built objects to ensure compatibility with `mwldeppc`.

- Strips empty sections
- Generates section symbols for all allocatable sections
- Where possible, replaces section-relative relocations with direct relocations.
- Adds an ` (asm)` suffix to the file symbol. (For matching progress calculation)

```shell
# input and output can be the same
$ dtk elf fixup file.o file.o
```

### elf2dol

Creates a DOL file from the provided ELF file.

```shell
$ dtk elf2dol input.elf output.dol
```

### map

Processes CodeWarrior map files and provides information about symbols and TUs.

```shell
$ dtk map entries Game.MAP 'Unit.o'
# Outputs all symbols that are referenced by Unit.o
# This is useful for finding deduplicated weak functions,
# which only show on first use in the link map.

$ dtk map symbol Game.MAP 'Function__5ClassFv'
# Outputs reference information for Function__5ClassFv
# CodeWarrior link maps can get very deeply nested,
# so this is useful for emitting direct references
# in a readable format.
```

### shasum

Calculate and verify SHA-1 hashes.

```shell
$ dtk shasum baserom.dol
949c5ed7368aef547e0b0db1c3678f466e2afbff  baserom.dol

$ dtk shasum -c baserom.sha1 
baserom.dol: OK
```
