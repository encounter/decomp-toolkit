pub mod asm;
pub mod config;
pub mod dol;
pub mod dwarf;
pub mod elf;
pub mod file;
pub mod map;
pub mod nested;
pub mod rel;
pub mod rso;

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
