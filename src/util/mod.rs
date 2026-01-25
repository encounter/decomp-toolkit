use std::{borrow::Cow, ops::Deref};

pub mod alf;
pub mod asm;
pub mod bin2c;
pub mod comment;
pub mod config;
pub mod crypto;
pub mod dep;
pub mod diff;
pub mod dol;
pub mod dwarf;
pub mod elf;
pub mod extab;
pub mod file;
pub mod lcf;
pub mod map;
pub mod map_exe;
pub mod ncompress;
pub mod nested;
pub mod nlzss;
pub mod path;
pub mod rarc;
pub mod read;
pub mod reader;
pub mod rel;
pub mod rso;
pub mod signatures;
pub mod split;
pub mod take_seek;
pub mod toposort;
pub mod u8_arc;
pub mod wad;
pub mod xex;
pub mod xex_imports;
pub mod xpdb;

#[inline]
pub const fn align_up(value: u32, align: u32) -> u32 { (value + (align - 1)) & !(align - 1) }

/// Creates a fixed-size array reference from a slice.
#[macro_export]
macro_rules! array_ref {
    ($slice:expr, $offset:expr, $size:expr) => {{
        #[inline]
        fn to_array<T>(slice: &[T]) -> &[T; $size] {
            unsafe { &*(slice.as_ptr() as *const [_; $size]) }
        }
        to_array(&$slice[$offset..$offset + $size])
    }};
}

/// Creates a fixed-size mutable array reference from a slice.
#[macro_export]
macro_rules! array_ref_mut {
    ($slice:expr, $offset:expr, $size:expr) => {{
        #[inline]
        fn to_array_mut<T>(slice: &mut [T]) -> &mut [T; $size] {
            unsafe { &mut *(slice.as_mut_ptr() as *mut [_; $size]) }
        }
        to_array_mut(&mut $slice[$offset..$offset + $size])
    }};
}

/// Compile-time assertion.
#[macro_export]
macro_rules! static_assert {
    ($condition:expr) => {
        const _: () = core::assert!($condition);
    };
}

pub trait IntoCow<'a, B>
where B: ToOwned + ?Sized
{
    fn into_cow(self) -> Cow<'a, B>;
}

pub trait ToCow<'a, B>
where B: ToOwned + ?Sized
{
    fn to_cow(&'a self) -> Cow<'a, B>;
}

impl<'a, O> IntoCow<'a, <O as Deref>::Target> for O
where
    O: Deref + Clone + 'a,
    <O as Deref>::Target: ToOwned<Owned = O>,
{
    fn into_cow(self) -> Cow<'a, <O as Deref>::Target> { Cow::Owned(self) }
}

impl<'a, B> ToCow<'a, B> for B
where B: ToOwned + ?Sized
{
    fn to_cow(&'a self) -> Cow<'a, B> { Cow::Borrowed(self) }
}

pub enum Bytes<'a> {
    Borrowed(&'a [u8]),
    Owned(Box<[u8]>),
}

impl Bytes<'_> {
    pub fn into_owned(self) -> Box<[u8]> {
        match self {
            Bytes::Borrowed(s) => Box::from(s),
            Bytes::Owned(b) => b,
        }
    }
}

impl AsRef<[u8]> for Bytes<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Bytes::Borrowed(s) => s,
            Bytes::Owned(b) => b,
        }
    }
}
