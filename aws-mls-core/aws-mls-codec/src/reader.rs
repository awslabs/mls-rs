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

pub struct ReadWithCount<R> {
    inner: R,
    count: usize,
}

impl<R> ReadWithCount<R> {
    pub fn new(r: R) -> Self {
        Self { inner: r, count: 0 }
    }

    #[inline]
    pub fn bytes_read(&self) -> usize {
        self.count
    }
}

impl<R: Reader> Reader for ReadWithCount<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<(), crate::Error> {
        self.inner.read(buf)?;
        self.count += buf.len();
        Ok(())
    }
}

impl<R> From<R> for ReadWithCount<R> {
    fn from(r: R) -> Self {
        Self::new(r)
    }
}
