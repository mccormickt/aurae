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
use std::sync::{
    Arc,
    mpsc::{Sender, channel},
};

use anyhow::{Context, anyhow};
use hypervisor::Hypervisor;
use nix::libc::EFD_NONBLOCK;
use vmm::{VmmThreadHandle, api::ApiRequest};
use vmm_sys_util::eventfd::EventFd;

pub struct Manager {
    pub events: EventFd,
    pub sender: Option<Sender<ApiRequest>>,
    hypervisor: Arc<dyn Hypervisor>,
    debug: EventFd,
    vmm_thread: Option<VmmThreadHandle>,
}

impl Manager {
    pub fn new() -> Result<Self, anyhow::Error> {
        let debug = EventFd::new(EFD_NONBLOCK)
            .context("Failed to create event monitor")?;
        let api_evt = EventFd::new(EFD_NONBLOCK)
            .context("Failed to create API eventfd")?;

        let hypervisor = hypervisor::new()
            .map_err(|e| anyhow!("Failed to instantiate hypervisor: {e}"))?;

        Ok(Self {
            hypervisor,
            debug,
            sender: None,
            events: api_evt,
            vmm_thread: None,
        })
    }

    pub fn start(&mut self) -> Result<(), anyhow::Error> {
        let (sender, receiver) = channel();

        let version =
            vmm::VmmVersionInfo::new("auraed", env!("CARGO_PKG_VERSION"));
        let vmm_thread = vmm::start_vmm_thread(
            version,
            &None,
            None,
            self.events.try_clone()?,
            sender.clone(),
            receiver,
            self.debug.try_clone()?,
            &seccompiler::SeccompAction::Allow,
            self.hypervisor.clone(),
            false, // no_shutdown
            true,  // landlock_enable
        )
        .map_err(|e| anyhow!("Failed to start VMM thread: {e}"))?;
        self.sender = Some(sender);
        self.vmm_thread = Some(vmm_thread);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Manager;

    #[test]
    fn manager_construction_never_panics() {
        let result = std::panic::catch_unwind(Manager::new);
        assert!(result.is_ok(), "Manager::new panicked");
    }
}
