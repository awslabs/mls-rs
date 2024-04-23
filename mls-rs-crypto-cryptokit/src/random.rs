extern "C" {
    fn random_bytes(ptr: *const u8, len: u64) -> u64;
}

pub fn fill(buf: &mut [u8]) -> bool {
    let rv = unsafe { random_bytes(buf.as_mut_ptr(), buf.len() as u64) };
    rv == 1
}

#[cfg(test)]
mod test {
    #[test]
    fn fill() {
        let init_val = 0xA0u8;
        let mut buf = [init_val; 1024];
        let rv = super::fill(&mut buf);
        assert!(rv);
        assert!(buf.iter().any(|&x| x != init_val));
    }
}
