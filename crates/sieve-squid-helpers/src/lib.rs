//! Squid helpers: `sieve-acl-helper` decides which requests are allowed, and
//! `sieve-proxy-auth` checks device proxy credentials.

pub mod acl;
pub mod auth;
pub mod protocol;
