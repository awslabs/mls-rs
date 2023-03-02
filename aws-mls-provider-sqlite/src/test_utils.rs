use rand::RngCore;
pub fn gen_rand_bytes(size: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0; size];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}
