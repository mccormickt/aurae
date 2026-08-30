/* -------------------------------------------------------------------------- *\
 *                |   █████╗ ██╗   ██╗██████╗  █████╗ ███████╗ |              *
 *                |  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔════╝ |              *
 *                |  ███████║██║   ██║██████╔╝███████║█████╗   |              *
 *                |  ██╔══██║██║   ██║██╔══██╗██╔══██║██╔══╝   |              *
 *                |  ██║  ██║╚██████╔╝██║  ██║██║  ██║███████╗ |              *
 *                |  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ |              *
 *                +--------------------------------------------+              *
 *                                                                            *
 *                         Distributed Systems Runtime                        *
 * -------------------------------------------------------------------------- *
 * Copyright 2022 - 2024, the aurae contributors                              *
 * SPDX-License-Identifier: Apache-2.0                                        *
\* -------------------------------------------------------------------------- */

mod error;
mod manager;
mod proxy;
mod virtual_machine;
mod virtual_machines;
mod vm_service;

use std::fmt;

pub(crate) use vm_service::VmService;

/// Unforgeable capability carried only by the host-to-cell VM control path.
///
/// Its `Debug` implementation never exposes the secret, because `Cell` and
/// `NestedAuraed` are routinely included in diagnostic output.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct VmControlToken(String);

impl VmControlToken {
    pub(crate) fn generate() -> Self {
        Self(format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4()))
    }

    pub(crate) fn from_secret(secret: String) -> Self {
        Self(secret)
    }

    pub(crate) fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for VmControlToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VmControlToken([REDACTED])")
    }
}
