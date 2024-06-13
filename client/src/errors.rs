use thiserror::Error;

#[derive(Debug, Error)]
pub enum Errors {
    #[error("detecting NAT type failded")]
    NatDetectFailed,
}
