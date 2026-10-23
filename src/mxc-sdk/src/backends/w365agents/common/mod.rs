// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MXC `w365_agents` backend — streaming exec bridge to the DesktopControl.Exec
//! capability over the RemotingInterface relay. See
//! `docs/superpowers/specs/2026-07-20-mxc-relay-exec-design.md`.

pub mod config;
pub mod cp;
pub mod dp;
pub mod exec;
pub mod http;
pub mod id;
pub mod metadata;
pub mod runner;
pub mod secret;

pub use runner::W365AgentsRunner;
