//! Error handling for the `repository` module.
//!

use std::fmt;
use std::convert::Infallible;
use bcder::decode::{DecodeError, ContentError};
use crate::crypto::keys::SignatureVerificationError;


//------------ InspectionError -----------------------------------------------

#[derive(Debug)]
pub struct InspectionError{
    inner: ContentError,
}

impl InspectionError {
    pub fn new(err: impl Into<ContentError>) -> Self {
        InspectionError { inner: err.into() }
    }
}

impl From<ContentError> for InspectionError {
    fn from(err: ContentError) -> InspectionError {
        InspectionError { inner: err }
    }
}

impl From<InspectionError> for ContentError {
    fn from(err: InspectionError) -> Self {
        err.inner
    }
}

impl fmt::Display for InspectionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f)
    }
}


//------------ VerificationError ---------------------------------------------

#[derive(Debug)]
pub struct VerificationError{
    inner: ContentError,
}

impl VerificationError {
    pub fn new(err: impl Into<ContentError>) -> Self {
        VerificationError { inner: err.into() }
    }
}

impl From<ContentError> for VerificationError {
    fn from(err: ContentError) -> VerificationError {
        VerificationError { inner: err }
    }
}

impl From<SignatureVerificationError> for VerificationError {
    fn from(err: SignatureVerificationError) -> Self {
        ContentError::from(err).into()
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f)
    }
}


//------------ ValidationError -----------------------------------------------

#[derive(Debug)]
pub struct ValidationError{
    inner: ValidationErrorKind,
}

#[derive(Debug)]
enum ValidationErrorKind {
    Decoding(DecodeError<Infallible>),
    Inspection(InspectionError),
    Verification(VerificationError),
}

impl From<DecodeError<Infallible>> for ValidationError {
    fn from(err: DecodeError<Infallible>) -> ValidationError {
        ValidationError {
            inner: ValidationErrorKind::Decoding(err)
        }
    }
}

impl From<InspectionError> for ValidationError {
    fn from(err: InspectionError) -> ValidationError {
        ValidationError {
            inner: ValidationErrorKind::Inspection(err)
        }
    }
}

impl From<VerificationError> for ValidationError {
    fn from(err: VerificationError) -> ValidationError {
        ValidationError {
            inner: ValidationErrorKind::Verification(err)
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.inner {
            ValidationErrorKind::Decoding(ref inner) => inner.fmt(f),
            ValidationErrorKind::Inspection(ref inner) => inner.fmt(f),
            ValidationErrorKind::Verification(ref inner) => inner.fmt(f),
        }
    }
}

