//! `client codec`: not provided yet by this adapter.

use crate::common::{Envelope, Failure};

pub async fn run(_args: &[String]) -> i32 {
    Envelope::new("codec")
        .fail(&Failure::input(
            "codec is not implemented by the async-opcua adapter",
        ))
        .emit()
}
