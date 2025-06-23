// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use core::time::Duration;
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

/// Wasm-compatible representation of a timestamp.
///
/// This type represents a point in time after 1970. The precision is seconds.
///
/// Since `MlsTime` always represents a timestamp after 1970, it can be trivially
/// converted to/from a standard library [`Duration`] value (measuring the time since
/// the start of the Unix epoch).
#[cfg_attr(all(feature = "ffi", not(test)), safer_ffi_gen::ffi_type)]
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, MlsSize, MlsEncode, MlsDecode,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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

impl core::ops::Sub<MlsTime> for MlsTime {
    type Output = Duration;

    fn sub(self, rhs: Self) -> Duration {
        Duration::from_secs(self.seconds - rhs.seconds)
    }
}

impl core::ops::Sub<Duration> for MlsTime {
    type Output = MlsTime;

    fn sub(self, rhs: Duration) -> MlsTime {
        MlsTime::from(self.seconds - rhs.as_secs())
    }
}

impl core::ops::Add<Duration> for MlsTime {
    type Output = MlsTime;

    fn add(self, rhs: Duration) -> MlsTime {
        MlsTime::from(self.seconds + rhs.as_secs())
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
