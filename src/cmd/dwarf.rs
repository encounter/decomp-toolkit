use std::{
    collections::{btree_map, BTreeMap},
    io::{stdout, Cursor, Read, Write},
    ops::Bound::{Excluded, Unbounded},
    str::from_utf8,
};

use anyhow::{anyhow, bail, Context, Result};
use argp::FromArgs;
use object::{
    elf, Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget, Section,
};
use syntect::{
    highlighting::{Color, HighlightIterator, HighlightState, Highlighter, Theme, ThemeSet},
    parsing::{ParseState, ScopeStack, SyntaxReference, SyntaxSet},
};
use typed_path::Utf8NativePathBuf;

use crate::{
    util::{
        dwarf::{
            process_compile_unit, process_cu_tag, process_overlay_branch, read_debug_section,
            should_skip_tag, tag_type_string, AttributeKind, TagKind,
        },
        file::buf_writer,
        path::native_path,
    },
    vfs::open_file,
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing DWARF 1.1 information.
#[argp(subcommand, name = "dwarf")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Dump(DumpArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Dumps DWARF 1.1 info from an object or archive.
#[argp(subcommand, name = "dump")]
pub struct DumpArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// Input object. (ELF or archive)
    in_file: Utf8NativePathBuf,
    #[argp(option, short = 'o', from_str_fn(native_path))]
    /// Output file. (Or directory, for archive)
    out: Option<Utf8NativePathBuf>,
    #[argp(switch)]
    /// Disable color output.
    no_color: bool,
    #[argp(switch)]
    /// Attempt to reconstruct tags that have been removed by the linker, e.g.
    /// tags from unused functions or functions that have been inlined away.
    include_erased: bool,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Dump(c_args) => dump(c_args),
    }
}

fn dump(args: DumpArgs) -> Result<()> {
    // Load syntect
    let theme_set: ThemeSet =
        syntect::dumps::from_binary(include_bytes!("../../assets/syntax/default.themedump"));
    let syntax_set: SyntaxSet = syntect::dumps::from_binary(include_bytes!(
        "../../assets/syntax/default_newlines.packdump"
    ));
    let theme = theme_set.themes.get("Solarized (dark)").context("Failed to load theme")?;
    let syntax = syntax_set.find_syntax_by_name("C++").context("Failed to find syntax")?.clone();

    let mut file = open_file(&args.in_file, true)?;
    let buf = file.map()?;
    if buf.starts_with(b"!<arch>\n") {
        let mut archive = ar::Archive::new(buf);
        while let Some(result) = archive.next_entry() {
            let mut e = match result {
                Ok(e) => e,
                Err(e) => bail!("Failed to read archive entry: {:?}", e),
            };
            let name = String::from_utf8_lossy(e.header().identifier()).to_string();
            let mut data = vec![0u8; e.header().size() as usize];
            e.read_exact(&mut data)?;
            let obj_file = object::read::File::parse(&*data)?;
            let debug_section = match obj_file.section_by_name(".debug") {
                Some(section) => {
                    log::info!("Processing '{}'", name);
                    section
                }
                None => {
                    log::warn!("Object '{}' missing .debug section", name);
                    continue;
                }
            };
            if let Some(out_path) = &args.out {
                // TODO make a basename method
                let name = name.trim_start_matches("D:").replace('\\', "/");
                let name = name.rsplit_once('/').map(|(_, b)| b).unwrap_or(&name);
                let file_path = out_path.join(format!("{}.txt", name));
                let mut file = buf_writer(&file_path)?;
                dump_debug_section(&args, &mut file, &obj_file, debug_section)?;
                file.flush()?;
            } else if args.no_color {
                println!("\n// File {}:", name);
                dump_debug_section(&args, &mut stdout(), &obj_file, debug_section)?;
            } else {
                let mut writer = HighlightWriter::new(syntax_set.clone(), syntax.clone(), theme);
                writeln!(writer, "\n// File {}:", name)?;
                dump_debug_section(&args, &mut writer, &obj_file, debug_section)?;
            }
        }
    } else {
        let obj_file = object::read::File::parse(buf)?;
        let debug_section = obj_file
            .section_by_name(".debug")
            .ok_or_else(|| anyhow!("Failed to locate .debug section"))?;
        if let Some(out_path) = &args.out {
            let mut file = buf_writer(out_path)?;
            dump_debug_section(&args, &mut file, &obj_file, debug_section)?;
            file.flush()?;
        } else if args.no_color {
            dump_debug_section(&args, &mut stdout(), &obj_file, debug_section)?;
        } else {
            let mut writer = HighlightWriter::new(syntax_set, syntax, theme);
            dump_debug_section(&args, &mut writer, &obj_file, debug_section)?;
        }
    }
    Ok(())
}

fn dump_debug_section<W>(
    args: &DumpArgs,
    w: &mut W,
    obj_file: &object::File<'_>,
    debug_section: Section,
) -> Result<()>
where
    W: Write + ?Sized,
{
    let mut data = debug_section.uncompressed_data()?.into_owned();

    // Apply relocations to data
    for (addr, reloc) in debug_section.relocations() {
        match reloc.flags() {
            RelocationFlags::Elf { r_type: elf::R_PPC_ADDR32 | elf::R_PPC_UADDR32 } => {
                let target = match reloc.target() {
                    RelocationTarget::Symbol(symbol_idx) => {
                        let symbol = obj_file.symbol_by_index(symbol_idx)?;
                        (symbol.address() as i64 + reloc.addend()) as u32
                    }
                    _ => bail!("Invalid .debug relocation target"),
                };
                data[addr as usize..addr as usize + 4].copy_from_slice(&target.to_be_bytes());
            }
            RelocationFlags::Elf { r_type: elf::R_PPC_NONE } => {}
            _ => bail!("Unhandled .debug relocation type {:?}", reloc.kind()),
        }
    }

    let mut reader = Cursor::new(&*data);
    let info = read_debug_section(&mut reader, obj_file.endianness().into(), args.include_erased)?;

    for (&addr, tag) in &info.tags {
        log::debug!("{}: {:?}", addr, tag);
    }

    let mut units = Vec::<String>::new();
    if let Some((_, mut tag)) = info.tags.first_key_value() {
        loop {
            match tag.kind {
                TagKind::Padding => {
                    // TODO
                }
                TagKind::MwOverlayBranch => {
                    let branch = process_overlay_branch(tag)?;
                    writeln!(w, "\n/*\n    Overlay: {}", branch.name)?;
                    writeln!(w, "    Overlay ID: {}", branch.id)?;
                    writeln!(
                        w,
                        "    Code range: {:#010X} -> {:#010X}",
                        branch.start_address, branch.end_address
                    )?;

                    if let Some(unit_addr) = branch.compile_unit {
                        let tag = info
                            .tags
                            .get(&unit_addr)
                            .ok_or_else(|| anyhow!("Failed to get CompileUnit"))?;
                        let unit = process_compile_unit(tag)?;
                        writeln!(w, "    Compile unit: {}", unit.name)?;
                    }

                    writeln!(w, "*/")?;
                }
                TagKind::CompileUnit => {
                    let unit = process_compile_unit(tag)?;
                    if units.contains(&unit.name) {
                        // log::warn!("Duplicate unit '{}'", unit.name);
                    } else {
                        units.push(unit.name.clone());
                    }
                    writeln!(w, "\n/*\n    Compile unit: {}", unit.name)?;
                    if let Some(producer) = unit.producer {
                        writeln!(w, "    Producer: {}", producer)?;
                    }
                    if let Some(comp_dir) = unit.comp_dir {
                        writeln!(w, "    Compile directory: {}", comp_dir)?;
                    }
                    if let Some(language) = unit.language {
                        writeln!(w, "    Language: {}", language)?;
                    }
                    if let (Some(start), Some(end)) = (unit.start_address, unit.end_address) {
                        writeln!(w, "    Code range: {:#010X} -> {:#010X}", start, end)?;
                    }
                    if let Some(gcc_srcfile_name_offset) = unit.gcc_srcfile_name_offset {
                        writeln!(
                            w,
                            "    GCC Source File Name Offset: {:#010X}",
                            gcc_srcfile_name_offset
                        )?;
                    }
                    if let Some(gcc_srcinfo_offset) = unit.gcc_srcinfo_offset {
                        writeln!(w, "    GCC Source Info Offset: {:#010X}", gcc_srcinfo_offset)?;
                    }
                    writeln!(w, "*/")?;

                    let mut children = tag.children(&info.tags);

                    // merge in erased tags
                    let range = match tag.next_sibling(&info.tags) {
                        Some(next) => (Excluded(tag.key), Excluded(next.key)),
                        None => (Excluded(tag.key), Unbounded),
                    };
                    for (_, child) in info.tags.range(range) {
                        if child.is_erased_root {
                            children.push(child);
                        }
                    }
                    children.sort_by_key(|x| x.key);

                    let mut typedefs = BTreeMap::<u32, Vec<u32>>::new();
                    for child in children {
                        let tag_type = match process_cu_tag(&info, child) {
                            Ok(tag_type) => tag_type,
                            Err(e) => {
                                log::error!(
                                    "Failed to process tag {:X} (unit {}): {}",
                                    child.key,
                                    unit.name,
                                    e
                                );
                                writeln!(
                                    w,
                                    "// ERROR: Failed to process tag {:X} ({:?})",
                                    child.key, child.kind
                                )?;
                                continue;
                            }
                        };
                        if should_skip_tag(&tag_type, child.is_erased) {
                            continue;
                        }
                        match tag_type_string(&info, &typedefs, &tag_type, child.is_erased) {
                            Ok(s) => writeln!(w, "{}", s)?,
                            Err(e) => {
                                log::error!(
                                    "Failed to emit tag {:X} (unit {}): {}",
                                    child.key,
                                    unit.name,
                                    e
                                );
                                writeln!(
                                    w,
                                    "// ERROR: Failed to emit tag {:X} ({:?})",
                                    child.key, child.kind
                                )?;
                                continue;
                            }
                        }

                        if let TagKind::Typedef = child.kind {
                            // TODO fundamental typedefs?
                            if let Some(ud_type_ref) =
                                child.reference_attribute(AttributeKind::UserDefType)
                            {
                                match typedefs.entry(ud_type_ref) {
                                    btree_map::Entry::Vacant(e) => {
                                        e.insert(vec![child.key]);
                                    }
                                    btree_map::Entry::Occupied(e) => {
                                        e.into_mut().push(child.key);
                                    }
                                }
                            }
                        }
                    }
                }
                kind => bail!("Unhandled root tag type {:?}", kind),
            }

            if let Some(next) = tag.next_sibling(&info.tags) {
                tag = next;
            } else {
                break;
            }
        }
    }
    // log::info!("Link order:");
    // for x in units {
    //     log::info!("{}", x);
    // }
    Ok(())
}

struct HighlightWriter<'a> {
    line: String,
    highlighter: Highlighter<'a>,
    parse_state: ParseState,
    highlight_state: HighlightState,
    syntax_set: SyntaxSet,
}

impl<'a> HighlightWriter<'a> {
    pub fn new(
        syntax_set: SyntaxSet,
        syntax: SyntaxReference,
        theme: &'a Theme,
    ) -> HighlightWriter<'a> {
        let highlighter = Highlighter::new(theme);
        let highlight_state = HighlightState::new(&highlighter, ScopeStack::new());
        HighlightWriter {
            line: String::new(),
            highlighter,
            syntax_set,
            parse_state: ParseState::new(&syntax),
            highlight_state,
        }
    }
}

#[inline]
fn blend_fg_color(fg: Color, bg: Color) -> Color {
    if fg.a == 0xff {
        return fg;
    }
    let ratio = fg.a as u32;
    let r = (fg.r as u32 * ratio + bg.r as u32 * (255 - ratio)) / 255;
    let g = (fg.g as u32 * ratio + bg.g as u32 * (255 - ratio)) / 255;
    let b = (fg.b as u32 * ratio + bg.b as u32 * (255 - ratio)) / 255;
    Color { r: r as u8, g: g as u8, b: b as u8, a: 255 }
}

impl Write for HighlightWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let str = from_utf8(buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        for s in str.split_inclusive('\n') {
            self.line.push_str(s);
            if self.line.ends_with('\n') {
                self.flush()?;
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.line.is_empty() {
            return Ok(());
        }
        let ops = self
            .parse_state
            .parse_line(&self.line, &self.syntax_set)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let iter = HighlightIterator::new(
            &mut self.highlight_state,
            &ops[..],
            &self.line,
            &self.highlighter,
        );
        for (style, text) in iter {
            print!(
                "\x1b[48;2;{};{};{}m",
                style.background.r, style.background.g, style.background.b
            );
            let fg = blend_fg_color(style.foreground, style.background);
            print!("\x1b[38;2;{};{};{}m{}", fg.r, fg.g, fg.b, text);
        }
        print!("\x1b[0m");
        self.line.clear();
        Ok(())
    }
}
