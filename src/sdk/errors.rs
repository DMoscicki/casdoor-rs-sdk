use std::fmt::Display;

use crate::StatusCode;

#[derive(Debug)]
#[non_exhaustive]
pub struct SdkError {
    pub code: StatusCode,
    pub inner: SdkInnerError,
}

impl SdkError {
    pub fn new(code: StatusCode, inner: impl Into<SdkInnerError>) -> Self {
        Self { code, inner: inner.into() }
    }
}

impl Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl std::error::Error for SdkError {}

#[derive(Debug)]
pub enum SdkInnerError {
    StringError(String),
    ReqwestError(reqwest::Error),
    SerdeUrlencodedSerError(serde_urlencoded::ser::Error),
    Oauth2UrlParseError(url::ParseError),
    Oauth2RequestTokenError(String),
    JwtError(jsonwebtoken::errors::Error),
}

impl Display for SdkInnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdkInnerError::StringError(error) => write!(f, "{error}"),
            SdkInnerError::ReqwestError(error) => write!(f, "{error}"),
            SdkInnerError::SerdeUrlencodedSerError(error) => write!(f, "{error}"),
            SdkInnerError::Oauth2UrlParseError(error) => write!(f, "{error}"),
            SdkInnerError::Oauth2RequestTokenError(error) => write!(f, "{error}"),
            SdkInnerError::JwtError(error) => write!(f, "{error}"),
        }
    }
}

impl From<reqwest::Error> for SdkError {
    fn from(e: reqwest::Error) -> Self {
        Self {
            code: if let Some(status) = e.status() {
                status
            } else if e.is_timeout() {
                StatusCode::REQUEST_TIMEOUT
            } else if e.is_request() {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            },
            inner: SdkInnerError::ReqwestError(e),
        }
    }
}

impl<T: Into<String>> From<T> for SdkInnerError {
    fn from(value: T) -> Self {
        Self::StringError(value.into())
    }
}

impl From<serde_urlencoded::ser::Error> for SdkError {
    fn from(value: serde_urlencoded::ser::Error) -> Self {
        Self::new(StatusCode::BAD_REQUEST, SdkInnerError::SerdeUrlencodedSerError(value))
    }
}

impl From<url::ParseError> for SdkError {
    fn from(value: url::ParseError) -> Self {
        Self::new(StatusCode::BAD_REQUEST, SdkInnerError::Oauth2UrlParseError(value))
    }
}

impl From<jsonwebtoken::errors::Error> for SdkError {
    fn from(value: jsonwebtoken::errors::Error) -> Self {
        Self::new(StatusCode::BAD_REQUEST, SdkInnerError::JwtError(value))
    }
}

impl<RE, TE> From<oauth2::RequestTokenError<RE, TE>> for SdkError
where
    RE: std::error::Error + 'static,
    TE: oauth2::ErrorResponse + 'static,
{
    fn from(value: oauth2::RequestTokenError<RE, TE>) -> Self {
        match value {
            oauth2::RequestTokenError::ServerResponse(_) => Self::new(StatusCode::INTERNAL_SERVER_ERROR, value.to_string()),
            oauth2::RequestTokenError::Request(_) => Self::new(StatusCode::BAD_REQUEST, value.to_string()),
            oauth2::RequestTokenError::Parse(_, _) => Self::new(StatusCode::INTERNAL_SERVER_ERROR, value.to_string()),
            oauth2::RequestTokenError::Other(_) => Self::new(StatusCode::INTERNAL_SERVER_ERROR, value.to_string()),
        }
    }
}