use core::time::Duration;

#[cfg(all(not(target_arch = "wasm32"), feature = "std"))]
pub type SystemTimeError = std::time::SystemTimeError;

#[cfg(any(target_arch = "wasm32", not(feature = "std")))]
pub type SystemTimeError = core::convert::Infallible;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(all(not(target_arch = "wasm32"), feature = "std"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// WASM compatible system time for use with MLS.
pub struct MlsTime(std::time::SystemTime);

#[cfg(all(not(target_arch = "wasm32"), feature = "std"))]
impl MlsTime {
    /// Current system time.
    pub fn now() -> Self {
        Self(std::time::SystemTime::now())
    }

    /// Create a timestamp from a duration since unix epoch.
    pub fn from_duration_since_epoch(duration: Duration) -> Option<MlsTime> {
        std::time::SystemTime::UNIX_EPOCH
            .checked_add(duration)
            .map(MlsTime)
    }

    /// Number of seconds since the unix epoch.
    pub fn seconds_since_epoch(&self) -> Result<u64, std::time::SystemTimeError> {
        Ok(self.0.duration_since(std::time::UNIX_EPOCH)?.as_secs())
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(inline_js = r#"
export function date_now() {
  return Date.now();
}"#)]
extern "C" {
    fn date_now() -> f64;
}

#[cfg(any(target_arch = "wasm32", not(feature = "std")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MlsTime(u64);

#[cfg(any(target_arch = "wasm32", not(feature = "std")))]
impl MlsTime {
    #[cfg(target_arch = "wasm32")]
    pub fn now() -> Self {
        Self((date_now() / 1000.0) as u64)
    }

    pub fn from_duration_since_epoch(duration: Duration) -> Option<MlsTime> {
        Some(MlsTime(duration.as_secs()))
    }

    pub fn seconds_since_epoch(&self) -> Result<u64, SystemTimeError> {
        Ok(self.0)
    }
}
