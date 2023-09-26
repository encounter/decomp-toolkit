use std::{borrow::Cow, ops::Deref};

pub mod asm;
pub mod comment;
pub mod config;
pub mod dep;
pub mod dol;
pub mod dwarf;
pub mod elf;
pub mod file;
pub mod lcf;
pub mod map;
pub mod nested;
pub mod rarc;
pub mod rel;
pub mod rso;
pub mod signatures;
pub mod split;
pub mod yaz0;

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
