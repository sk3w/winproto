#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unknown error")]
    UnknownError,
}

pub type Result<T> = std::result::Result<T, Error>;