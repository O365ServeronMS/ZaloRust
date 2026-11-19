//! On-disk storage migrations and helpers for encrypted local databases.
//!
//! `sqlcipher` owns the D2 decision of the shadow-DB design: a random
//! 32-byte key, DPAPI-wrapped on Windows (`CryptProtectData`), stored next
//! to the SQLCipher database it protects. The module is deliberately small
//! and dependency-free beyond `rusqlite` so it can be reused by the shadow
//! pipeline, the import CLI and the probes.

pub mod sqlcipher;
