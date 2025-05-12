// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use core::time::Duration;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg_attr(all(feature = "ffi", not(test)), safer_ffi_gen::ffi_type)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct MlsTime {
    seconds: u64,
}

impl MlsTime {
    /// Create a timestamp from a duration since unix epoch.
    pub fn from_duration_since_epoch(duration: Duration) -> MlsTime {
        Self::from(duration)
    }

    /// Number of seconds since the unix epoch.
    pub fn seconds_since_epoch(&self) -> u64 {
        self.seconds
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "std"))]
impl MlsTime {
    /// Current system time.
    pub fn now() -> Self {
        Self {
            seconds: std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

impl From<u64> for MlsTime {
    fn from(value: u64) -> Self {
        Self { seconds: value }
    }
}

impl From<Duration> for MlsTime {
    fn from(value: Duration) -> MlsTime {
        Self {
            seconds: value.as_secs(),
        }
    }
}

impl From<MlsTime> for Duration {
    fn from(value: MlsTime) -> Duration {
        Duration::from_secs(value.seconds)
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "std"))]
#[derive(Debug, thiserror::Error)]
#[error("Overflow while adding {0:?}")]
/// Overflow in time conversion.
pub struct TimeOverflow(Duration);

#[cfg(all(not(target_arch = "wasm32"), feature = "std"))]
impl TryFrom<MlsTime> for std::time::SystemTime {
    type Error = TimeOverflow;

    fn try_from(value: MlsTime) -> Result<std::time::SystemTime, Self::Error> {
        let duration = Duration::from(value);
        std::time::SystemTime::UNIX_EPOCH
            .checked_add(duration)
            .ok_or(TimeOverflow(duration))
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "std"))]
impl TryFrom<std::time::SystemTime> for MlsTime {
    type Error = std::time::SystemTimeError;

    fn try_from(value: std::time::SystemTime) -> Result<MlsTime, Self::Error> {
        let duration = value.duration_since(std::time::SystemTime::UNIX_EPOCH)?;
        Ok(MlsTime::from(duration))
    }
}

#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
#[wasm_bindgen(inline_js = r#"
export function date_now() {
  return Date.now();
}"#)]
extern "C" {
    fn date_now() -> f64;
}

#[cfg(all(target_arch = "wasm32", target_os = "emscripten"))]
extern "C" {
    #[link_name = "emscripten_date_now"]
    fn date_now() -> f64;
}

#[cfg(target_arch = "wasm32")]
impl MlsTime {
    pub fn now() -> Self {
        Self {
            seconds: (unsafe { date_now() } / 1000.0) as u64,
        }
    }
}
