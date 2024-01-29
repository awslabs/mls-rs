use alloc::vec::Vec;

#[cfg(all(not(mls_build_async), feature = "rayon"))]
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use super::{CipherSuiteProvider, HpkeCiphertext, HpkePublicKey, HpkeSecretKey};

#[cfg(all(not(mls_build_async), feature = "rayon"))]
pub(crate) fn mm_hpke_seal<P: CipherSuiteProvider>(
    cs: &P,
    info: &[u8],
    aad: Option<&[u8]>,
    pt: &[&[u8]],
    remote_keys: &[Vec<&HpkePublicKey>],
) -> Result<Vec<Vec<HpkeCiphertext>>, P::Error> {
    use rayon::iter::IndexedParallelIterator;

    pt.par_iter()
        .zip(remote_keys.par_iter())
        .map(|(pt, remote_keys)| {
            remote_keys
                .par_iter()
                .map(|remote_pub| cs.hpke_seal(remote_pub, info, aad, pt))
                .collect::<Result<_, _>>()
        })
        .collect()
}

#[cfg(any(mls_build_async, not(feature = "rayon")))]
#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub(crate) async fn mm_hpke_seal<P: CipherSuiteProvider>(
    cs: &P,
    info: &[u8],
    aad: Option<&[u8]>,
    pt: &[&[u8]],
    remote_keys: &[Vec<&HpkePublicKey>],
) -> Result<Vec<Vec<HpkeCiphertext>>, P::Error> {
    let mut ct = Vec::new();

    for (pt, remote_keys) in pt.iter().zip(remote_keys.iter()) {
        ct.push(Vec::new());

        for remote_pub in remote_keys {
            if let Some(ct) = ct.last_mut() {
                ct.push(cs.hpke_seal(remote_pub, info, aad, pt).await?);
            }
        }
    }

    Ok(ct)
}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
pub(crate) async fn mm_hpke_open<P: CipherSuiteProvider>(
    cs: &P,
    ct: &[&[HpkeCiphertext]],
    self_index: (usize, usize),
    local_secret: &HpkeSecretKey,
    local_public: &HpkePublicKey,
    info: &[u8],
    aad: Option<&[u8]>,
) -> Result<Option<Vec<u8>>, P::Error> {
    let (i, j) = self_index;

    match ct.get(i).and_then(|ct| ct.get(j)) {
        Some(ct) => Ok(Some(
            cs.hpke_open(ct, local_secret, local_public, info, aad)
                .await?,
        )),
        None => Ok(None),
    }
}
