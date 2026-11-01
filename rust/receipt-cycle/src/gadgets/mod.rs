// The purpose-specific parent relation consumes this in the next layer;
// keeping it private prevents an incomplete receipt acceptance API.
#[allow(dead_code)]
pub(crate) mod sha256;

// This remains disconnected from acceptance until the typed suite is frozen.
#[allow(dead_code)]
pub(crate) mod poseidon;
