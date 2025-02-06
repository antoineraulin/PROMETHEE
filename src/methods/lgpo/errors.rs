use std::fmt;

use serde::de;

#[derive(Debug)]
pub enum LgpoError {
    Message(String),
    Eof,
    InvalidFormat(String),
    Custom(String),
}

impl std::error::Error for LgpoError {}
impl fmt::Display for LgpoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LgpoError::Message(s) => write!(f, "Error: {}", s),
            LgpoError::Eof => write!(f, "Unexpected EOF"),
            LgpoError::InvalidFormat(s) => write!(f, "Invalid format: {}", s),
            LgpoError::Custom(s) => write!(f, "{}", s),
        }
    }
}

impl de::Error for LgpoError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        LgpoError::Custom(msg.to_string())
    }
}