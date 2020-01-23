#![feature(proc_macro_hygiene, decl_macro)]

extern crate rocket;
#[macro_use]
extern crate rocket_contrib;

pub mod constants;

#[macro_use]
pub mod common;
pub mod protocols;

pub mod server;
