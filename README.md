# jeff [![Build Status]][actions]

[Build Status]: https://github.com/encounter/decomp-toolkit/actions/workflows/build.yml/badge.svg
[actions]: https://github.com/encounter/decomp-toolkit/actions

https://youtu.be/0OzXZGA1k3s

Forked from and inspired by [encounter's GC/Wii decomp toolkit](https://github.com/encounter/decomp-toolkit), jeff is 
a decomp-toolkit meant for disassembling Xbox 360 executables (xex files). It aims to assist potential Xbox 360 decompilation projects with
the same benefits that encounter's toolkit provides, including function boundary analysis, relocation restorations, splits, and integration
with other decompilation tools like [objdiff](https://github.com/encounter/objdiff) and
[decomp.me](https://decomp.me).

Much like the original GC/Wii decomp toolkit, jeff aims to automate as much of the decompilation setup process as possible,
allowing developers to spend less time configuring a project and more time focusing on what matters most in a decomp: matching code.

I had made jeff with the goal of starting up a [decomp for Dance Central 3](https://github.com/rjkiv/dc3-decomp),
but realized the potential jeff has to work with several other Xbox 360 games, and thus, tried to add support for that to the best of my ability.

**DISCLAIMER**: Although I genuinely tried my best to get jeff working with the pool of xex files I had to test with,
**I make absolutely zero guarantees that this will work out of the box with every last Xbox 360 game! Expect bugs!**

If you spot a bug or crash, please submit an issue, and I will try my best to help you through it.

For use in a new decompilation project, see [jeff-template](https://github.com/rjkiv/jeff-template), which provides a
project structure and build system that uses jeff under the hood.

## Features
- Can extract an exe from an xex using: `xex extract <xex location>`.
You supply the xex, and the underlying exe will be extracted to the same directory - it'll even have its original name the developers gave it!
- Can print out information about an xex using: `xex info <xex location>`.
This aims to replicate the behavior of the original xextool by xorloser.
- Can write down inferred splits, symbols, and COFFs from an xex using: `xex info <config.yml>`.
This is NOT meant to be run on its own, but rather part of a build system, such as the one in the dtk-template above.

## Known Issues/Hacks
- Jump table detection works a lot differently for an xex than it does a GC/Wii DOL.
There are multiple different kinds of jump table versions that MSVC likes to use, and the code that detects them is rather hacky.
The code checks for a specific sequence of known instructions and infers the jump table type from there.
This can result in some jump tables being "guessed" or missed during function detection.
- When parsing .map files, the last split of a section will not get added.
This is because during development, I found that the last split would sometimes conflict with the inferred boundaries of nearby objects/symbols, which would cause errors.
So, if you are using jeff and your game has a map, you will have to remember to manually add the last split of each of your exe's sections.
- Parsing/applying .pdb files currently has limited support.
- Trying to link the generated COFFs into a final exe and comparing sections of it against the original extracted exe (like what the GC/Wii toolkit does with elfs/dols)
is currently unsupported, as it was out of the initial scope of the project.
- Because this was forked from encounter's GC/Wii toolkit, there is naturally still a lot of loose GC/Wii tailored code in this codebase that needs removing/refactoring.

## Want to contribute?
Whether you want to add a new feature, or would like to fix one of the known issues, I would love your contribution!
Feel free to fork this repo and submit a PR containing your change. Every little improvement helps jeff become a better resource for the greater decomping community!

Although this is an Xbox 360 centric repo, feel free to join the [GC/Wii Decompilation Discord](https://discord.gg/hKx3FJJgrV) as well!

## Acknowledgements
- [encounter](https://github.com/encounter) - not only for his work on the original GC/Wii toolkit as well as several other decompilation tools, but for his constant help and guidance throughout jeff's creation process
- [The RB3 Decomp and its contributors](https://github.com/DarkRTA/rb3) - for providing additional guidance and suggestions throughout development
