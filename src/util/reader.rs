use std::{
    io,
    io::{Error, ErrorKind, Read, Seek, SeekFrom},
};

use io::Write;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Endian {
    Big,
    Little,
}

impl From<object::Endianness> for Endian {
    fn from(value: object::Endianness) -> Self {
        match value {
            object::Endianness::Big => Endian::Big,
            object::Endianness::Little => Endian::Little,
        }
    }
}

impl Endian {
    pub fn flip(self) -> Self {
        match self {
            Endian::Big => Endian::Little,
            Endian::Little => Endian::Big,
        }
    }
}

pub const DYNAMIC_SIZE: usize = 0;

pub const fn struct_size<const N: usize>(fields: [usize; N]) -> usize {
    let mut result = 0;
    let mut i = 0;
    while i < N {
        let size = fields[i];
        if size == DYNAMIC_SIZE {
            // Dynamically sized
            return DYNAMIC_SIZE;
        }
        result += size;
        i += 1;
    }
    result
}

#[inline]
pub fn skip_bytes<const N: usize, R>(reader: &mut R) -> io::Result<()>
where R: Read + Seek + ?Sized {
    reader.seek(SeekFrom::Current(N as i64))?;
    Ok(())
}

pub trait FromReader: Sized {
    type Args;

    const STATIC_SIZE: usize;

    fn from_reader_args<R>(reader: &mut R, e: Endian, args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized;

    fn from_reader<R>(reader: &mut R, e: Endian) -> io::Result<Self>
    where
        R: Read + Seek + ?Sized,
        Self::Args: Default,
    {
        Self::from_reader_args(reader, e, Default::default())
    }
}

pub trait FromBytes<const N: usize>: Sized {
    fn from_bytes(bytes: [u8; N], e: Endian) -> Self;
}

macro_rules! impl_from_reader {
    ($($t:ty),*) => {
        $(
            impl FromBytes<{ <$t>::STATIC_SIZE }> for $t {
                #[inline]
                fn from_bytes(bytes: [u8; Self::STATIC_SIZE], e: Endian) -> Self {
                    match e {
                        Endian::Big => Self::from_be_bytes(bytes),
                        Endian::Little => Self::from_le_bytes(bytes),
                    }
                }
            }

            impl FromReader for $t {
                const STATIC_SIZE: usize = std::mem::size_of::<Self>();

                type Args = ();

                #[inline]
                fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
                where R: Read + Seek + ?Sized {
                    let mut buf = [0u8; Self::STATIC_SIZE];
                    reader.read_exact(&mut buf)?;
                    Ok(Self::from_bytes(buf, e))
                }
            }
        )*
    };
}

impl_from_reader!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

impl<const N: usize> FromReader for [u8; N] {
    type Args = ();

    const STATIC_SIZE: usize = N;

    #[inline]
    fn from_reader_args<R>(reader: &mut R, _e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        let mut buf = [0u8; N];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl<const N: usize> FromReader for [u32; N] {
    type Args = ();

    const STATIC_SIZE: usize = N * u32::STATIC_SIZE;

    #[inline]
    fn from_reader_args<R>(reader: &mut R, e: Endian, _args: Self::Args) -> io::Result<Self>
    where R: Read + Seek + ?Sized {
        let mut buf = [0u32; N];
        reader.read_exact(unsafe {
            std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, Self::STATIC_SIZE)
        })?;
        if e == Endian::Big {
            for x in buf.iter_mut() {
                *x = u32::from_be(*x);
            }
        }
        Ok(buf)
    }
}

#[inline]
pub fn read_bytes<R>(reader: &mut R, count: usize) -> io::Result<Vec<u8>>
where R: Read + Seek + ?Sized {
    let mut buf = vec![0u8; count];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

#[inline]
pub fn read_vec<T, R>(reader: &mut R, count: usize, e: Endian) -> io::Result<Vec<T>>
where
    T: FromReader,
    T::Args: Default,
    R: Read + Seek + ?Sized,
{
    let mut vec = Vec::with_capacity(count);
    for _ in 0..count {
        vec.push(T::from_reader(reader, e)?);
    }
    Ok(vec)
}

#[inline]
pub fn read_vec_args<T, R>(
    reader: &mut R,
    count: usize,
    e: Endian,
    args: T::Args,
) -> io::Result<Vec<T>>
where
    T: FromReader,
    T::Args: Clone,
    R: Read + Seek + ?Sized,
{
    let mut vec = Vec::with_capacity(count);
    for _ in 0..count {
        vec.push(T::from_reader_args(reader, e, args.clone())?);
    }
    Ok(vec)
}

#[inline]
pub fn read_string<T, R>(reader: &mut R, e: Endian) -> io::Result<String>
where
    T: FromReader + TryInto<usize>,
    T::Args: Default,
    R: Read + Seek + ?Sized,
{
    let len = <T>::from_reader(reader, e)?
        .try_into()
        .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid string length"))?;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    String::from_utf8(buf).map_err(|e| Error::new(ErrorKind::InvalidData, e))
}

pub trait ToWriter: Sized {
    fn to_writer<W>(&self, writer: &mut W, e: Endian) -> io::Result<()>
    where W: Write + ?Sized;

    #[inline]
    fn to_writer_static<W>(&self, writer: &mut W, e: Endian) -> io::Result<()>
    where W: Write + ?Sized {
        writer.write_all(&self.to_bytes(e)?)
    }

    fn to_bytes(&self, e: Endian) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; self.write_size()];
        self.to_writer(&mut buf.as_mut_slice(), e)?;
        Ok(buf)
    }

    fn write_size(&self) -> usize;
}

macro_rules! impl_to_writer {
    ($($t:ty),*) => {
        $(
            impl ToWriter for $t {
                fn to_writer<W>(&self, writer: &mut W, e: Endian) -> io::Result<()>
                where W: Write + ?Sized {
                    writer.write_all(&match e {
                        Endian::Big => self.to_be_bytes(),
                        Endian::Little => self.to_le_bytes(),
                    })
                }

                fn to_bytes(&self, e: Endian) -> io::Result<Vec<u8>> {
                    Ok(match e {
                        Endian::Big => self.to_be_bytes(),
                        Endian::Little => self.to_le_bytes(),
                    }.to_vec())
                }

                fn write_size(&self) -> usize {
                    std::mem::size_of::<Self>()
                }
            }
        )*
    };
}

impl_to_writer!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

impl<const N: usize> ToWriter for [u8; N] {
    fn to_writer<W>(&self, writer: &mut W, _e: Endian) -> io::Result<()>
    where W: Write + ?Sized {
        writer.write_all(self)
    }

    fn write_size(&self) -> usize { N }
}

impl ToWriter for &[u8] {
    fn to_writer<W>(&self, writer: &mut W, _e: Endian) -> io::Result<()>
    where W: Write + ?Sized {
        writer.write_all(self)
    }

    fn write_size(&self) -> usize { self.len() }
}

impl ToWriter for Vec<u8> {
    fn to_writer<W>(&self, writer: &mut W, _e: Endian) -> io::Result<()>
    where W: Write + ?Sized {
        writer.write_all(self)
    }

    fn write_size(&self) -> usize { self.len() }
}

impl<const N: usize> ToWriter for [u32; N] {
    fn to_writer<W>(&self, writer: &mut W, e: Endian) -> io::Result<()>
    where W: Write + ?Sized {
        for &value in self {
            value.to_writer(writer, e)?;
        }
        Ok(())
    }

    fn write_size(&self) -> usize { N * u32::STATIC_SIZE }
}

pub fn write_vec<T, W>(writer: &mut W, vec: &[T], e: Endian) -> io::Result<()>
where
    T: ToWriter,
    W: Write + ?Sized,
{
    for item in vec {
        item.to_writer(writer, e)?;
    }
    Ok(())
}
