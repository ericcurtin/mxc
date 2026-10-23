// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

string_marker! {
    /// The `provision` phase of the state-aware configuration contract.
    pub struct ProvisionPhase => "provision";
}

/// A validated provision request selected by its concrete containment backend.
#[derive(Debug)]
pub enum ProvisionRequest {
    /// An IsolationSession provision request.
    IsolationSession(IsolationSessionProvisionRequest),
    /// A Windows Sandbox provision request.
    WindowsSandbox(WindowsSandboxProvisionRequest),
    /// A WSLC provision request.
    Wslc(WslcProvisionRequest),
    /// A W365 Agents provision request.
    W365Agents(W365AgentsProvisionRequest),
}

mod containment;
mod isolation_session;
mod w365_agents;
mod windows_sandbox;
mod wslc;

pub use containment::{probe_containment, Containment, ContainmentProbeError};
pub use isolation_session::{
    IsolationSessionContainment, IsolationSessionNetwork, IsolationSessionNetworkAllow,
    IsolationSessionNetworkEgress, IsolationSessionNetworkIngress, IsolationSessionProvision,
    IsolationSessionProvisionRequest, StateAwareIsolationSession,
};
pub use w365_agents::{
    StateAwareW365Agents, StateAwareW365AgentsDeprovision, StateAwareW365AgentsExec,
    StateAwareW365AgentsStart, StateAwareW365AgentsStop, W365AgentsContainment, W365AgentsExec,
    W365AgentsProvision, W365AgentsProvisionRequest, W365AgentsStart, W365AgentsStop,
};
pub use windows_sandbox::{WindowsSandboxContainment, WindowsSandboxProvisionRequest};
pub use wslc::{StateAwareWslc, WslcContainment, WslcProvision, WslcProvisionRequest};
