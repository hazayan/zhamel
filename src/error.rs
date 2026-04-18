use core::fmt;

#[cfg(target_os = "uefi")]
use uefi::Status;

#[cfg(not(target_os = "uefi"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Unsupported,
    InvalidParameter,
    Other,
}

#[cfg(not(target_os = "uefi"))]
impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Status::Unsupported => write!(f, "UNSUPPORTED"),
            Status::InvalidParameter => write!(f, "INVALID_PARAMETER"),
            Status::Other => write!(f, "OTHER"),
        }
    }
}

#[derive(Debug)]
pub enum BootError {
    Unsupported(&'static str),
    InvalidData(&'static str),
    Uefi(Status),
}

impl fmt::Display for BootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootError::Unsupported(msg) => write!(f, "unsupported: {}", msg),
            BootError::InvalidData(msg) => write!(f, "invalid data: {}", msg),
            BootError::Uefi(status) => write!(f, "uefi error: {}", status),
        }
    }
}

impl BootError {
    pub fn status(&self) -> Status {
        match self {
            #[cfg(target_os = "uefi")]
            BootError::Unsupported(_) => Status::UNSUPPORTED,
            #[cfg(not(target_os = "uefi"))]
            BootError::Unsupported(_) => Status::Unsupported,
            #[cfg(target_os = "uefi")]
            BootError::InvalidData(_) => Status::INVALID_PARAMETER,
            #[cfg(not(target_os = "uefi"))]
            BootError::InvalidData(_) => Status::InvalidParameter,
            BootError::Uefi(status) => *status,
        }
    }
}

pub type Result<T> = core::result::Result<T, BootError>;

#[cfg(test)]
mod tests {
    extern crate alloc;
    extern crate std;

    use alloc::format;

    use super::{BootError, Status};

    #[cfg(target_os = "uefi")]
    fn unsupported_status() -> Status {
        Status::UNSUPPORTED
    }

    #[cfg(not(target_os = "uefi"))]
    fn unsupported_status() -> Status {
        Status::Unsupported
    }

    #[cfg(target_os = "uefi")]
    fn invalid_parameter_status() -> Status {
        Status::INVALID_PARAMETER
    }

    #[cfg(not(target_os = "uefi"))]
    fn invalid_parameter_status() -> Status {
        Status::InvalidParameter
    }

    #[cfg(target_os = "uefi")]
    fn passthrough_status() -> Status {
        Status::ABORTED
    }

    #[cfg(not(target_os = "uefi"))]
    fn passthrough_status() -> Status {
        Status::Other
    }

    #[test]
    fn test_status_mapping() {
        let err = BootError::Unsupported("nope");
        assert_eq!(err.status(), unsupported_status());
        let err = BootError::InvalidData("bad");
        assert_eq!(err.status(), invalid_parameter_status());
        let err = BootError::Uefi(passthrough_status());
        assert_eq!(err.status(), passthrough_status());
    }

    #[test]
    fn test_display_formats() {
        let err = BootError::Unsupported("feature");
        assert_eq!(format!("{err}"), "unsupported: feature");
        let err = BootError::InvalidData("payload");
        assert_eq!(format!("{err}"), "invalid data: payload");
        let err = BootError::Uefi(unsupported_status());
        assert_eq!(format!("{err}"), "uefi error: UNSUPPORTED");
    }
}
