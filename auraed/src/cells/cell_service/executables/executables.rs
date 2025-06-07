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

use tracing::{debug, error};

use super::{
    Executable, ExecutableName, ExecutableSpec, ExecutablesError, Result,
};
use std::os::unix::process::ExitStatusExt;
use std::{collections::HashMap, process::ExitStatus};

type Cache = HashMap<ExecutableName, Executable>;

/// An in-memory store for the list of executables created with Aurae.
#[derive(Debug, Default)]
pub struct Executables {
    cache: Cache,
}

impl Executables {
    pub fn start<T: Into<ExecutableSpec>>(
        &mut self,
        executable_spec: T,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<&Executable> {
        let executable_spec = executable_spec.into();

        // TODO: replace with try_insert when it becomes stable
        // Check if there was already an executable with the same name.
        if self.cache.contains_key(&executable_spec.name) {
            return Err(ExecutablesError::ExecutableExists {
                executable_name: executable_spec.name,
            });
        }

        let executable_name = executable_spec.name.clone();
        let mut executable = Executable::new(executable_spec);

        // start the exe before we add it to the cache, as otherwise a failure leads to the
        // executable remaining in the cache and start cannot be called again.
        executable.start(uid, gid).map_err(|e| {
            ExecutablesError::FailedToStartExecutable {
                executable_name: executable_name.clone(),
                source: e,
            }
        })?;

        // `or_insert` will always insert as we've already assured ourselves that the key does not
        // exist.
        let inserted_executable =
            self.cache.entry(executable_name).or_insert_with(|| executable);

        Ok(inserted_executable)
    }

    pub fn get(&self, executable_name: &ExecutableName) -> Result<&Executable> {
        let Some(executable) = self.cache.get(executable_name) else {
            return Err(ExecutablesError::ExecutableNotFound {
                executable_name: executable_name.clone(),
            });
        };
        Ok(executable)
    }

    pub async fn stop(
        &mut self,
        executable_name: &ExecutableName,
    ) -> Result<ExitStatus> {
        use std::io::ErrorKind;

        let Some(executable) = self.cache.get_mut(executable_name) else {
            return Err(ExecutablesError::ExecutableNotFound {
                executable_name: executable_name.clone(),
            });
        };

        // Try to kill the process and handle possible errors
        let exit_status_result = executable.kill().await;

        // Remove the executable from cache regardless of kill result
        // This ensures we clean up our cache even if kill fails
        let executable = self
            .cache
            .remove(executable_name)
            .expect("executable should be in cache since we just got it");

        // Now handle the kill result
        let exit_status = match exit_status_result {
            Ok(Some(status)) => {
                // Successfully killed and got exit status
                Ok(status)
            }
            Ok(None) => {
                // Process was never started
                Err(ExecutablesError::ExecutableNotFound {
                    executable_name: executable.name,
                })
            }
            Err(e)
                if e.kind() == ErrorKind::NotFound
                    || e.raw_os_error() == Some(libc::ESRCH)
                    || e.raw_os_error() == Some(libc::ECHILD) =>
            {
                // Process already exited or doesn't exist anymore
                // Create a simulated exit status since we can't get the real one
                Ok(ExitStatus::from_raw(0))
            }
            Err(e) => {
                // Other errors
                Err(ExecutablesError::FailedToStopExecutable {
                    executable_name: executable_name.clone(),
                    source: e,
                })
            }
        }?;

        Ok(exit_status)
    }

    /// Stops all executables concurrently
    pub async fn broadcast_stop(&mut self) {
        let mut names = vec![];
        for exe in self.cache.values_mut() {
            let pid_info = exe.pid().ok().and_then(|p| p.map(|p| p.as_raw()));
            match exe.kill().await {
                Ok(Some(status)) => {
                    debug!(
                        "Process {} (PID: {:?}) was successfully killed with status: {:?}",
                        exe.name, pid_info, status
                    );
                }
                Ok(None) => {
                    debug!("Process {} was never started", exe.name);
                }
                Err(e) => {
                    error!(
                        "Failed to stop executable {} (PID: {:?}): {}",
                        exe.name, pid_info, e
                    );
                }
            }
            names.push(exe.name.clone())
        }

        for name in names {
            let _ = self.cache.remove(&name);
        }
    }
}
