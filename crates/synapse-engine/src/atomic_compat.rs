//! `fetch_update` that stays warning-free across Rust versions.
//!
//! Rust 1.99 deprecated `Atomic*::fetch_update` in favor of `try_update` (same signature and
//! semantics, just renamed). Our minimum supported Rust is 1.88 (`rust-version` in the workspace
//! `Cargo.toml`; the Docker image builds on 1.94), where `try_update` doesn't exist, so we can't
//! switch yet — but CI lints on the latest stable with `-D warnings`, which turns the deprecation
//! into a hard error. Routing every call through this one trait keeps the `#[allow(deprecated)]`
//! in a single place instead of sprinkled over the engine.
//!
//! When the minimum supported Rust reaches 1.99, change the body below to `self.try_update(..)`
//! (or delete this module and call `try_update` directly).

use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};

pub(crate) trait FetchUpdateCompat {
    type Value;

    /// Same contract as `Atomic*::fetch_update`: retries `f` until the compare-exchange
    /// succeeds or `f` returns `None`; returns the previous value in `Ok` (updated) or `Err`
    /// (`f` declined).
    fn fetch_update_compat<F>(
        &self,
        set_order: Ordering,
        fetch_order: Ordering,
        f: F,
    ) -> Result<Self::Value, Self::Value>
    where
        F: FnMut(Self::Value) -> Option<Self::Value>;
}

macro_rules! impl_fetch_update_compat {
    ($atomic:ty, $int:ty) => {
        impl FetchUpdateCompat for $atomic {
            type Value = $int;

            #[allow(deprecated)]
            fn fetch_update_compat<F>(
                &self,
                set_order: Ordering,
                fetch_order: Ordering,
                f: F,
            ) -> Result<$int, $int>
            where
                F: FnMut($int) -> Option<$int>,
            {
                self.fetch_update(set_order, fetch_order, f)
            }
        }
    };
}

impl_fetch_update_compat!(AtomicUsize, usize);
impl_fetch_update_compat!(AtomicU64, u64);
impl_fetch_update_compat!(AtomicI64, i64);
