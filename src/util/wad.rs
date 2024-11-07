use std::{
    io,
    io::{BufRead, Read, Seek},
};

use aes::cipher::{BlockDecryptMut, KeyIvInit};
use anyhow::{bail, Result};
use nodtool::nod::{Ticket, TmdHeader};
use sha1::{Digest, Sha1};
use size::Size;
use zerocopy::{big_endian::*, FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

use crate::{
    array_ref_mut, static_assert,
    util::read::{read_box_slice, read_from},
};

// TODO: other WAD types?
pub const WAD_MAGIC: [u8; 8] = [0x00, 0x00, 0x00, 0x20, 0x49, 0x73, 0x00, 0x00];

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(4))]
pub struct WadHeader {
    pub header_size: U32,
    pub wad_type: [u8; 0x2],
    pub wad_version: U16,
    pub cert_chain_size: U32,
    pub _reserved1: [u8; 0x4],
    pub ticket_size: U32,
    pub tmd_size: U32,
    pub data_size: U32,
    pub footer_size: U32,
}

static_assert!(size_of::<WadHeader>() == 0x20);

#[derive(Clone, Debug, PartialEq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(4))]
pub struct ContentMetadata {
    pub content_id: U32,
    pub content_index: U16,
    pub content_type: U16,
    pub size: U64,
    pub hash: HashBytes,
}

static_assert!(size_of::<ContentMetadata>() == 0x24);

impl ContentMetadata {
    #[inline]
    pub fn iv(&self) -> [u8; 0x10] {
        let mut iv = [0u8; 0x10];
        *array_ref_mut!(iv, 0, 2) = self.content_index.get().to_be_bytes();
        iv
    }
}

const ALIGNMENT: usize = 0x40;

#[inline(always)]
pub fn align_up(value: u64, alignment: u64) -> u64 { (value + alignment - 1) & !(alignment - 1) }

pub type HashBytes = [u8; 20];
pub type KeyBytes = [u8; 16];

type Aes128Cbc = cbc::Decryptor<aes::Aes128>;

#[derive(Debug, Clone)]
pub struct WadFile {
    pub header: WadHeader,
    pub title_key: KeyBytes,
    pub fake_signed: bool,
    pub raw_cert_chain: Box<[u8]>,
    pub raw_ticket: Box<[u8]>,
    pub raw_tmd: Box<[u8]>,
    pub content_offset: u64,
}

impl WadFile {
    pub fn ticket(&self) -> &Ticket {
        Ticket::ref_from_bytes(&self.raw_ticket).expect("Invalid ticket alignment")
    }

    pub fn tmd(&self) -> &TmdHeader {
        TmdHeader::ref_from_prefix(&self.raw_tmd).expect("Invalid TMD alignment").0
    }

    pub fn contents(&self) -> &[ContentMetadata] {
        let (_, cmd_data) =
            TmdHeader::ref_from_prefix(&self.raw_tmd).expect("Invalid TMD alignment");
        <[ContentMetadata]>::ref_from_bytes(cmd_data).expect("Invalid CMD alignment")
    }

    pub fn content_offset(&self, content_index: u16) -> u64 {
        let contents = self.contents();
        let mut offset = self.content_offset;
        for content in contents.iter().take(content_index as usize) {
            offset = align_up(offset + content.size.get(), ALIGNMENT as u64);
        }
        offset
    }

    pub fn trailer_offset(&self) -> u64 {
        let contents = self.contents();
        let mut offset = self.content_offset;
        for content in contents.iter() {
            offset = align_up(offset + content.size.get(), ALIGNMENT as u64);
        }
        offset
    }
}

pub fn process_wad<R>(reader: &mut R) -> Result<WadFile>
where R: BufRead + Seek + ?Sized {
    let header: WadHeader = read_from(reader)?;
    let mut offset = align_up(header.header_size.get() as u64, ALIGNMENT as u64);

    reader.seek(io::SeekFrom::Start(offset))?;
    let raw_cert_chain: Box<[u8]> = read_box_slice(reader, header.cert_chain_size.get() as usize)?;
    offset = align_up(offset + header.cert_chain_size.get() as u64, ALIGNMENT as u64);

    reader.seek(io::SeekFrom::Start(offset))?;
    let raw_ticket: Box<[u8]> = read_box_slice(reader, header.ticket_size.get() as usize)?;
    offset = align_up(offset + header.ticket_size.get() as u64, ALIGNMENT as u64);

    reader.seek(io::SeekFrom::Start(offset))?;
    let raw_tmd: Box<[u8]> = read_box_slice(reader, header.tmd_size.get() as usize)?;
    offset = align_up(offset + header.tmd_size.get() as u64, ALIGNMENT as u64);

    let content_offset = offset;
    let mut file = WadFile {
        header,
        title_key: [0; 16],
        fake_signed: false,
        raw_cert_chain,
        raw_ticket,
        raw_tmd,
        content_offset,
    };

    let mut title_key_found = false;
    if file.ticket().header.sig.iter().all(|&x| x == 0) {
        // Fake signed, try to determine common key index
        file.fake_signed = true;
        let contents = file.contents();
        if let Some(smallest_content) = contents.iter().min_by_key(|x| x.size.get()) {
            let mut ticket = file.ticket().clone();
            for i in 0..2 {
                ticket.common_key_idx = i;
                let title_key = ticket.decrypt_title_key()?;
                let offset = file.content_offset(smallest_content.content_index.get());
                reader.seek(io::SeekFrom::Start(offset))?;
                if verify_content(reader, smallest_content, &title_key)? {
                    file.title_key = title_key;
                    title_key_found = true;
                    break;
                }
            }
        }
        if !title_key_found {
            bail!("Failed to determine title key for fake signed WAD");
        }
    }
    if !title_key_found {
        let title_key = file.ticket().decrypt_title_key()?;
        file.title_key = title_key;
    }

    Ok(file)
}

pub fn verify_wad<R>(file: &WadFile, reader: &mut R) -> Result<()>
where R: Read + Seek + ?Sized {
    for content in file.contents() {
        let content_index = content.content_index.get();
        println!(
            "Verifying content {:08x} (size {})",
            content_index,
            Size::from_bytes(content.size.get())
        );
        let offset = file.content_offset(content_index);
        reader.seek(io::SeekFrom::Start(offset))?;
        if !verify_content(reader, content, &file.title_key)? {
            bail!("Content {:08x} hash mismatch", content_index);
        }
    }
    Ok(())
}

fn verify_content<R>(
    reader: &mut R,
    content: &ContentMetadata,
    title_key: &KeyBytes,
) -> Result<bool>
where
    R: Read + ?Sized,
{
    let mut buf = <[[u8; 0x10]]>::new_box_zeroed_with_elems(0x200)
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    // Read full padded size for decryption
    let read_size = align_up(content.size.get(), 0x40);
    let mut decryptor = Aes128Cbc::new(title_key.into(), (&content.iv()).into());
    let mut digest = Sha1::default();
    let mut read = 0;
    while read < read_size {
        let len = buf.len().min(usize::try_from(read_size - read).unwrap_or(usize::MAX));
        debug_assert_eq!(len % 0x10, 0);
        reader.read_exact(&mut buf.as_mut_bytes()[..len])?;
        for block in buf.iter_mut().take(len / 0x10) {
            decryptor.decrypt_block_mut(block.into());
        }
        // Only hash up to content size
        let hash_len = (read + len as u64).min(content.size.get()).saturating_sub(read) as usize;
        if hash_len > 0 {
            digest.update(&buf.as_bytes()[..hash_len]);
        }
        read += len as u64;
    }
    Ok(HashBytes::from(digest.finalize()) == content.hash)
}
