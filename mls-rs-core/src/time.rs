// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

use core::time::Duration;
use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

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
        Self {
            seconds: duration.as_secs(),
        }
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
