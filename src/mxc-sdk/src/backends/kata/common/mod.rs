// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `kata_common` - the Kata Containers backend.
//!
//! The backend drives `containerd-shim-kata-v2` directly, with no containerd
//! daemon and no Kubernetes. [`protobuf`], [`ttrpc`], and [`task_api`] are the
//! client for the shim's `containerd.task.v2.Task` service.

// The sandbox that uses this client arrives in the next commit.
#![allow(dead_code)]

pub(crate) mod protobuf;
pub(crate) mod task_api;
pub(crate) mod ttrpc;
