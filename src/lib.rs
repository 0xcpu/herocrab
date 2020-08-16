//! # herocrab
//! 
//! `herocrab` is a collection of routines to evaluate your environment
//! against multiple techniques used for example by malware to detect
//! analysis tools, sandboxes and so on.

#![feature(asm)]
#![feature(stmt_expr_attributes)]

#[cfg(windows)]
pub mod windows;
