use std::slice;

pub fn hash(input: &str) -> Box<[u8]> {
    unsafe {
        let mut hash_len: u64 = 0;
        let hash_ptr = hash_sha256(input.as_ptr(), input.len() as u64, &mut hash_len);
        Box::from_raw(slice::from_raw_parts_mut(hash_ptr, hash_len as usize))
    }
}

extern "C" {
    fn hash_sha256(input_ptr: *const u8, input_len: u64, hash_len_ptr: *mut u64) -> *mut u8;
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    #[test]
    fn test_highlight() {
        let input = "this is a string to be hashed with SHA-256";
        let actual = super::hash(input);
        let expected = hex!("c8236b75cad715d62c0f733d244a44d01e18b8c1797d1b9c55fa64aa7603cc6a");
        assert_eq!(actual.as_ref(), &expected);
    }
}
