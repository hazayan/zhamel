#![cfg_attr(not(feature = "host-coverage"), no_std)]

extern crate alloc;

#[cfg(feature = "host-coverage")]
pub mod args;

#[cfg(feature = "host-coverage")]
pub mod env {
    pub mod parser;
}

#[cfg(feature = "host-coverage")]
pub mod error;

#[cfg(feature = "host-coverage")]
pub mod kernel {
    pub mod elf;
    pub mod module;
    pub mod modulep;
    pub mod types;
}

#[cfg(feature = "host-coverage")]
pub mod mbr;
