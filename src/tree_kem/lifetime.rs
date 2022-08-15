use crate::time::MlsTime;
use thiserror::Error;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Debug, Error)]
pub enum LifetimeError {
    #[error(transparent)]
    SystemTimeError(#[from] crate::time::SystemTimeError),
    #[error("time overflow")]
    TimeOverflow,
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
    serde::Deserialize,
    serde::Serialize,
    Default,
)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Lifetime {
    pub not_before: u64,
    pub not_after: u64,
}

impl Lifetime {
    pub fn seconds(s: u64) -> Result<Self, LifetimeError> {
        let not_before = MlsTime::now().seconds_since_epoch()?;

        let not_after = not_before
            .checked_add(s)
            .ok_or(LifetimeError::TimeOverflow)?;

        Ok(Lifetime {
            not_before,
            not_after,
        })
    }

    pub fn days(d: u32) -> Result<Self, LifetimeError> {
        Self::seconds((d * 86400) as u64)
    }

    pub fn years(y: u8) -> Result<Self, LifetimeError> {
        Self::days(365 * y as u32)
    }

    pub fn within_lifetime(&self, time: MlsTime) -> Result<bool, LifetimeError> {
        let since_epoch = time.seconds_since_epoch()?;
        Ok(since_epoch >= self.not_before && since_epoch <= self.not_after)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use assert_matches::assert_matches;

    #[test]
    fn test_lifetime_overflow() {
        let res = Lifetime::seconds(u64::MAX);
        assert_matches!(res, Err(LifetimeError::TimeOverflow))
    }

    #[test]
    fn test_seconds() {
        let seconds = 10;
        let lifetime = Lifetime::seconds(seconds).unwrap();
        assert_eq!(lifetime.not_after - lifetime.not_before, 10);
    }

    #[test]
    fn test_days() {
        let days = 2;
        let lifetime = Lifetime::days(days).unwrap();

        assert_eq!(
            lifetime.not_after - lifetime.not_before,
            86400u64 * days as u64
        );
    }

    #[test]
    fn test_years() {
        let years = 2;
        let lifetime = Lifetime::years(years).unwrap();
        assert_eq!(
            lifetime.not_after - lifetime.not_before,
            86400 * 365 * years as u64
        );
    }

    #[test]
    fn test_bounds() {
        let test_lifetime = Lifetime {
            not_before: 5,
            not_after: 10,
        };

        assert!(!test_lifetime
            .within_lifetime(MlsTime::from_duration_since_epoch(Duration::from_secs(4)).unwrap())
            .unwrap());

        assert!(!test_lifetime
            .within_lifetime(MlsTime::from_duration_since_epoch(Duration::from_secs(11)).unwrap())
            .unwrap());

        assert!(test_lifetime
            .within_lifetime(MlsTime::from_duration_since_epoch(Duration::from_secs(5)).unwrap())
            .unwrap());

        assert!(test_lifetime
            .within_lifetime(MlsTime::from_duration_since_epoch(Duration::from_secs(10)).unwrap())
            .unwrap());

        assert!(test_lifetime
            .within_lifetime(MlsTime::from_duration_since_epoch(Duration::from_secs(6)).unwrap())
            .unwrap());
    }
}
