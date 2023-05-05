use core::fmt::{self, Display};

#[cfg(feature = "std")]
#[derive(Debug)]
pub struct AnyError(Box<dyn std::error::Error + Send + Sync>);

#[cfg(not(feature = "std"))]
#[derive(Debug)]
pub struct AnyError;

#[cfg(feature = "std")]
impl Display for AnyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AnyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

#[cfg(not(feature = "std"))]
impl Display for AnyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

pub trait IntoAnyError: core::fmt::Debug + Sized {
    #[cfg(feature = "std")]
    fn into_any_error(self) -> AnyError {
        self.into_dyn_error()
            .map_or_else(|_| AnyError(std::any::type_name::<Self>().into()), AnyError)
    }

    #[cfg(not(feature = "std"))]
    fn into_any_error(self) -> AnyError {
        AnyError
    }

    #[cfg(feature = "std")]
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Err(self)
    }
}

impl IntoAnyError for aws_mls_codec::Error {
    #[cfg(feature = "std")]
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

impl IntoAnyError for core::convert::Infallible {}
