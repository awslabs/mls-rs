use std::io::{self, Read};

pub struct ReadWithCount<R> {
    inner: R,
    count: usize,
}

impl<R> ReadWithCount<R> {
    pub fn new(r: R) -> Self {
        Self { inner: r, count: 0 }
    }

    pub fn bytes_read(&self) -> usize {
        self.count
    }
}

impl<R: Read> Read for ReadWithCount<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count += n;
        Ok(n)
    }
}

impl<R> From<R> for ReadWithCount<R> {
    fn from(r: R) -> Self {
        Self::new(r)
    }
}
