# Other approaches

## Manual assembly

With existing GameCube/Wii decompilation tooling, the setup process is very tedious and error-prone.
The general process is:

- Begin by disassembling the original binary with a tool like
  [doldisasm.py](https://gist.github.com/camthesaxman/a36f610dbf4cc53a874322ef146c4123). This produces one giant
  assembly file per section.
- Manually comb through the assembly files and fix many issues, like incorrect or missing relocations, incorrect or
  missing symbols, and more.
- Manually find-and-replace the auto-generated symbol names based on other sources, like other decompilation projects
  or a map file. (If you're lucky enough to have one)
- Manually determine data types and sizes, and convert them accordingly. (For example, `.4byte` -> `.float`, strings,
  etc)
- Manually split the assembly files into individual objects. This is a very tedious process, as it requires identifying
  the boundaries of each function, determining whether adjacent functions are related, finding associated
  data from each data section, and cut-and-pasting all of this into a new file.

Other downsides of this approach:

- Manually editing the assembly means that the result is not reproducible. You can't run the script again to
  make any updates, because your changes will be overwritten. This also means that the assembly files must be
  stored in version control, which is not ideal.
- Incorrectly splitting objects is very easy to do, and can be difficult to detect. For example, a `.ctors` entry _must_
  be located in the same object as the function it references, otherwise the linker will not generate the correct
  `.ctors` entry. `extab` and `extabindex` entries _must also_ be located in the same object as the function they
  reference, have a label and have the correct size, and have a direct relocation rather than a section-relative
  relocation. Otherwise, the linker will crash with a cryptic error message.
- Relying on assembly means that you need an assembler. For GameCube/Wii, this means devkitPro, which is a
  large dependency and an obstacle for new contributors. The assembler also has some quirks that don't interact well
  with `mwldeppc`, which means that the object files must be manually post-processed to fix these issues. (See the
  [elf fixup](/README.md#elf-fixup) command)

With decomp-toolkit:

- Many analysis steps are automated and highly accurate. Many DOL files can be analyzed and split into re-linkable
  objects with no configuration.
- Signature analysis automatically labels common functions and objects, and allows for more accurate relocation
  rebuilding.
- Any manual adjustments are stored in configuration files, which are stored in version control.
- Splitting is simplified by updating a configuration file. The analyzer will check for common issues, like
  incorrectly split `.ctors`/`.dtors`/`extab`/`extabindex` entries. If the user hasn't configured a split for these,
  the analyzer will automatically split them along with their associated functions to ensure that the linker will
  generate everything correctly. This means that matching code can be written without worrying about splitting all
  sections up front.
- The splitter generates object files directly, with no assembler required. This means that we can avoid the devkitPro
  requirement. (Although we can still generate assembly files for viewing, editing, and compatibility with other tools)

## dadosod

[dadosod](https://github.com/InusualZ/dadosod) is a newer replacement for `doldisasm.py`. It has more accurate function
and relocation analysis than `doldisasm.py`, as well as support for renaming symbols based on a map file. However, since
it operates as a one-shot assembly generator, it still suffers from many of the same issues described above.

## ppcdis

[ppcdis](https://github.com/SeekyCt/ppcdis) is one of the tools that inspired decomp-toolkit. It has more accurate
analysis than doldisasm.py, and has similar goals to decomp-toolkit. It's been used successfully in several
decompilation projects.

However, decomp-toolkit has a few advantages:

- Faster and more accurate analysis. (See [Analyzer features](/README.md#analyzer-features))
- Emits object files directly, with no assembler required.
- More robust handling of features like common BSS, `.ctors`/`.dtors`/`extab`/`extabindex`, and more.
- Requires very little configuration to start.
- Automatically labels common functions and objects with signature analysis.

## Honorable mentions

[splat](https://github.com/ethteck/splat) is a binary splitting tool for N64 and PSX. Some ideas from splat inspired
decomp-toolkit, like the symbol configuration format.
