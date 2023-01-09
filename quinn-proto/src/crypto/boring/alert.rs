use crate::crypto;
use boring_sys as bffi;
use std::ffi::{c_int, CStr};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

pub(super) enum AlertType {
    Warning,
    Fatal,
    Unknown,
}

impl AlertType {
    const ALERT_TYPE_WARNING: &'static str = "warning";
    const ALERT_TYPE_FATAL: &'static str = "fatal";
    const ALERT_TYPE_UNKNOWN: &'static str = "unknown";

    pub(super) fn from(value: i32) -> Self {
        match value {
            bffi::SSL3_AL_WARNING => Self::Warning,
            bffi::SSL3_AL_FATAL => Self::Fatal,
            _ => Self::Unknown,
        }
    }
}

impl Display for AlertType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Warning => f.write_str(Self::ALERT_TYPE_WARNING),
            Self::Fatal => f.write_str(Self::ALERT_TYPE_FATAL),
            _ => f.write_str(Self::ALERT_TYPE_UNKNOWN),
        }
    }
}

impl FromStr for AlertType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            Self::ALERT_TYPE_WARNING => Ok(Self::Warning),
            Self::ALERT_TYPE_FATAL => Ok(Self::Fatal),
            _ => Ok(Self::Unknown),
        }
    }
}

#[derive(Copy, Clone)]
pub(super) struct Alert(u8);

impl Alert {
    pub(super) fn from(value: u8) -> Self {
        Alert(value)
    }

    pub(super) fn handshake_failure() -> Self {
        Alert(bffi::SSL_AD_HANDSHAKE_FAILURE as u8)
    }

    pub(super) fn get_description(&self) -> &'static str {
        unsafe {
            CStr::from_ptr(bffi::SSL_alert_desc_string_long(self.0 as c_int))
                .to_str()
                .unwrap()
        }
    }

    pub(super) fn get_type(&self) -> AlertType {
        AlertType::from_str(unsafe {
            CStr::from_ptr(bffi::SSL_alert_type_string_long(self.0 as c_int))
                .to_str()
                .unwrap()
        })
        .unwrap()
    }
}

impl Display for Alert {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "SSL alert [{}]: {}", self.0, self.get_description())
    }
}

impl From<Alert> for crypto::TransportErrorCode {
    fn from(alert: Alert) -> Self {
        crypto::TransportErrorCode::crypto(alert.0)
    }
}

impl From<Alert> for crypto::TransportError {
    fn from(alert: Alert) -> Self {
        crypto::TransportError {
            code: alert.into(),
            frame: None,
            reason: alert.get_description().to_string(),
        }
    }
}
