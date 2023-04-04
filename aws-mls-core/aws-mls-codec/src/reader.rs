use crate::Error;

pub trait Reader {
    fn read(&mut self, bytes: &mut [u8]) -> Result<(), Error>;
}

impl<T> Reader for &mut T
where
    T: Reader,
{
    #[inline]
    fn read(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        (**self).read(bytes)
    }
}

impl Reader for &[u8] {
    #[inline]
    fn read(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        if bytes.len() > self.len() {
            return Err(Error::UnexpectedEOF);
        }

        let (read_slice, remaining) = self.split_at(bytes.len());
        bytes.copy_from_slice(read_slice);
        *self = remaining;

        Ok(())
    }
}
