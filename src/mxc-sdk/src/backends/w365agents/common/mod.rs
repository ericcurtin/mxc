// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MXC `w365_agents` backend — container lifecycle operations and streaming exec
//! bridge to `DesktopControl.Exec` over the RemotingInterface relay. See
//! `docs/backends/w365-agents/w365-agents.md`.

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
