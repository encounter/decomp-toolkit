use std::{io, io::Read};

use zerocopy::{FromBytes, FromZeros, IntoBytes};

#[inline(always)]
pub fn read_from<T, R>(reader: &mut R) -> io::Result<T>
where
    T: FromBytes + IntoBytes,
    R: Read + ?Sized,
{
    let mut ret = <T>::new_zeroed();
    reader.read_exact(ret.as_mut_bytes())?;
    Ok(ret)
}

#[inline(always)]
pub fn read_box_slice<T, R>(reader: &mut R, count: usize) -> io::Result<Box<[T]>>
where
    T: FromBytes + IntoBytes,
    R: Read + ?Sized,
{
    let mut ret = <[T]>::new_box_zeroed_with_elems(count)
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    reader.read_exact(ret.as_mut().as_mut_bytes())?;
    Ok(ret)
}
