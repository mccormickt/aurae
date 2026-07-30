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

use super::{Cell, CellName, CellSpec, CellsError, Result, cgroups::Cgroup};
use crate::cells::cell_service::cells::cells_cache::CellsCache;
use crate::init::network::Network;
use std::collections::HashMap;
use std::time::Instant;

type Cache = HashMap<CellName, Cell>;

/// The in-memory cache of cells ([Cell]) created with Aurae.
#[derive(Debug, Default)]
pub struct Cells {
    parent: Option<CellName>,
    cache: Cache,
    /// `CellService` also holds this handle. The network setup of a
    /// cell can find the `Network` of the host. It is `None` outside the
    /// daemon context, and such a cell cannot set `isolate_network`.
    network: Option<Network>,
}

// TODO: add to the impl
// [x] Get Cgroup from cell_name
// [ ] Get Cgroup from executable_name
// [ ] Get Cgroup from pid
// [ ] Get Cgroup and pids from executable_name

impl Cells {
    /// Build the root `Cells` collection of `CellService`. It has no
    /// parent. each cell name is a top-level name.
    pub fn new_root(network: Option<Network>) -> Self {
        Self { parent: None, cache: HashMap::new(), network }
    }

    /// Build a child `Cells` collection below `parent`. `Cell::allocate`
    /// uses it. The descendants share one `Network`.
    pub fn new(parent: CellName, network: Option<Network>) -> Self {
        Self { parent: Some(parent), cache: HashMap::new(), network }
    }

    /// If `cell_name` does not sit directly under our `parent`, return the
    /// name of the immediate child cell the operation should be forwarded
    /// to. Returns `None` when the name belongs directly to this
    /// collection (the caller handles it locally).
    fn child_to_forward(&self, cell_name: &CellName) -> Option<CellName> {
        if cell_name.is_child(self.parent.as_ref()) {
            return None;
        }

        Some(match &self.parent {
            None => cell_name.to_root(),
            Some(parent) => parent.to_child(cell_name).expect("child CellName"),
        })
    }

    pub(crate) async fn allocate(
        &mut self,
        cell_name: CellName,
        cell_spec: CellSpec,
    ) -> Result<&Cell> {
        // If the requested name doesn't sit directly under our `parent`,
        // walk down to the right child cell and forward the call.
        if let Some(child_cell_name) = self.child_to_forward(&cell_name) {
            let Some(child) = self.cache.get_mut(&child_cell_name) else {
                return Err(CellsError::CellNotFound {
                    cell_name: child_cell_name,
                });
            };
            return Box::pin(CellsCache::allocate(child, cell_name, cell_spec))
                .await;
        }

        if let Some(cell) = self.cache.get(&cell_name)
            && !cell.can_allocate()
        {
            return Err(CellsError::CellExists { cell_name });
        }

        if Cgroup::exists(&cell_name) {
            return Err(CellsError::CgroupIsNotACell {
                cell_name: cell_name.clone(),
            });
        }

        let _ = self.cache.remove(&cell_name);
        let network = self.network.clone();

        let cell = self
            .cache
            .entry(cell_name.clone())
            .or_insert_with(|| Cell::new(cell_name, cell_spec));

        // TODO: Should we remove the cell from the cache here if the call to
        //       allocate fails?
        cell.allocate(network).await?;

        Ok(cell)
    }

    pub(crate) async fn free(&mut self, cell_name: &CellName) -> Result<()> {
        if let Some(child_cell_name) = self.child_to_forward(cell_name) {
            let Some(child) = self.cache.get_mut(&child_cell_name) else {
                return Err(CellsError::CellNotFound {
                    cell_name: child_cell_name,
                });
            };
            return Box::pin(CellsCache::free(child, cell_name)).await;
        }

        let res = match self.cache.get_mut(cell_name) {
            Some(cell) => cell.free().await,
            None => {
                return if Cgroup::exists(cell_name) {
                    Err(CellsError::CgroupIsNotACell {
                        cell_name: cell_name.clone(),
                    })
                } else {
                    Err(CellsError::CellNotFound {
                        cell_name: cell_name.clone(),
                    })
                };
            }
        };

        if matches!(res, Err(CellsError::CellNotAllocated { .. })) {
            let _ = self.cache.remove(cell_name);
            return res;
        }

        res?;
        let _ = self.cache.remove(cell_name);
        Ok(())
    }

    pub(crate) fn get<F, R>(&mut self, cell_name: &CellName, f: F) -> Result<R>
    where
        F: Fn(&Cell) -> Result<R>,
    {
        if let Some(child_cell_name) = self.child_to_forward(cell_name) {
            let Some(child) = self.cache.get_mut(&child_cell_name) else {
                return Err(CellsError::CellNotFound {
                    cell_name: child_cell_name,
                });
            };
            return CellsCache::get(child, cell_name, f);
        }

        self.handle_cgroup_does_not_exist(cell_name)?;

        let Some(cell) = self.cache.get(cell_name) else {
            return Err(CellsError::CgroupIsNotACell {
                cell_name: cell_name.clone(),
            });
        };

        f(cell)
    }

    pub(crate) fn get_all<F, R>(&self, f: F) -> Result<Vec<Result<R>>>
    where
        F: Fn(&Cell) -> Result<R>,
    {
        Ok(self
            .cache
            .values()
            .filter_map(|cell| {
                let cell_name = cell.name();
                if !Cgroup::exists(cell_name) {
                    return None;
                };

                let res = f(cell);

                if matches!(res, Err(CellsError::CellNotAllocated { .. })) {
                    return None;
                }

                Some(res)
            })
            .collect())
    }

    fn handle_cgroup_does_not_exist(
        &mut self,
        cell_name: &CellName,
    ) -> Result<()> {
        if Cgroup::exists(cell_name) {
            return Ok(());
        }

        let Some(_cell) = self.cache.get(cell_name) else {
            // Cell doesn't exist & cgroup doesn't exist
            return Err(CellsError::CellNotFound {
                cell_name: cell_name.clone(),
            });
        };

        // Cell exist, but cgroup doesn't
        Err(CellsError::CgroupNotFound { cell_name: cell_name.clone() })
    }

    /// Frees sibling cells concurrently.
    pub(crate) async fn broadcast_free(&mut self) -> Result<()> {
        let results =
            futures::future::join_all(self.cache.values_mut().map(|cell| {
                let name = cell.name().clone();
                async move { (name, cell.free().await) }
            }))
            .await;

        let mut first_error = None;
        for (cell_name, result) in results {
            match result {
                Ok(()) => {
                    let _ = self.cache.remove(&cell_name);
                }
                Err(error) if first_error.is_none() => {
                    first_error = Some(error)
                }
                Err(_error) => {}
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Kills sibling cells concurrently.
    pub(crate) async fn broadcast_kill(&mut self) -> Result<()> {
        let results =
            futures::future::join_all(self.cache.values_mut().map(|cell| {
                let name = cell.name().clone();
                async move { (name, cell.kill().await) }
            }))
            .await;

        let mut first_error = None;
        for (cell_name, result) in results {
            match result {
                Ok(()) => {
                    let _ = self.cache.remove(&cell_name);
                }
                Err(error) if first_error.is_none() => {
                    first_error = Some(error)
                }
                Err(_error) => {}
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Performs synchronous best-effort cleanup during Drop.
    pub(crate) fn broadcast_kill_for_drop(&mut self) {
        let deadline = Instant::now() + super::nested_auraed::REAP_TIMEOUT;
        self.signal_kill_for_drop();
        self.reap_kill_for_drop(deadline);
    }

    pub(super) fn signal_kill_for_drop(&mut self) {
        for cell in self.cache.values_mut() {
            cell.signal_kill_for_drop();
        }
    }

    pub(super) fn reap_kill_for_drop(&mut self, deadline: Instant) {
        for cell in self.cache.values_mut() {
            cell.reap_kill_for_drop(deadline);
        }
        self.cache.clear();
    }
}

impl Drop for Cells {
    fn drop(&mut self) {
        self.broadcast_kill_for_drop();
    }
}

impl CellsCache for Cells {
    async fn allocate(
        &mut self,
        cell_name: CellName,
        cell_spec: CellSpec,
    ) -> Result<&Cell> {
        Cells::allocate(self, cell_name, cell_spec).await
    }

    async fn free(&mut self, cell_name: &CellName) -> Result<()> {
        Cells::free(self, cell_name).await
    }

    fn get<F, R>(&mut self, cell_name: &CellName, f: F) -> Result<R>
    where
        F: Fn(&Cell) -> Result<R>,
    {
        Cells::get(self, cell_name, f)
    }

    fn get_all<F, R>(&self, f: F) -> Result<Vec<Result<R>>>
    where
        F: Fn(&Cell) -> Result<R>,
    {
        Cells::get_all(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AURAED_RUNTIME, AuraedRuntime};
    use test_helpers::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_allocate() {
        skip_if_not_root!("test_allocate");
        // Docker's seccomp security profile (https://docs.docker.com/engine/security/seccomp/) blocks clone
        skip_if_seccomp!("test_cant_unfree");

        let _ = AURAED_RUNTIME.set(AuraedRuntime::default());

        let mut cells = Cells::default();
        assert!(cells.cache.is_empty());

        let cell_name = CellName::random_for_tests();
        let cell = CellSpec::new_for_tests();

        let _ =
            cells.allocate(cell_name.clone(), cell).await.expect("allocate");
        assert!(cells.cache.contains_key(&cell_name));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_duplicate_allocate_is_error() {
        skip_if_not_root!("test_duplicate_allocate_is_error");
        // Docker's seccomp security profile (https://docs.docker.com/engine/security/seccomp/) blocks clone
        skip_if_seccomp!("test_cant_unfree");

        let _ = AURAED_RUNTIME.set(AuraedRuntime::default());

        let mut cells = Cells::default();
        assert!(cells.cache.is_empty());

        let cell_name_in = CellName::random_for_tests();

        let cell_a = CellSpec::new_for_tests();
        let _ = cells
            .allocate(cell_name_in.clone(), cell_a)
            .await
            .expect("failed on first allocate");

        let cell_b = CellSpec::new_for_tests();
        assert!(matches!(
            cells.allocate(cell_name_in.clone(), cell_b).await,
            Err(CellsError::CellExists { cell_name }) if cell_name == cell_name_in
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_get() {
        skip_if_not_root!("test_get");
        // Docker's seccomp security profile (https://docs.docker.com/engine/security/seccomp/) blocks clone
        skip_if_seccomp!("test_get");

        let _ = AURAED_RUNTIME.set(AuraedRuntime::default());

        let mut cells = Cells::default();
        assert!(cells.cache.is_empty());

        let cell_name = CellName::random_for_tests();
        let cell = CellSpec::new_for_tests();
        let _ = cells
            .allocate(cell_name.clone(), cell)
            .await
            .expect("failed to allocate");

        cells.get(&cell_name, |_cell| Ok(())).expect("failed to get");
    }

    #[test]
    fn test_get_missing_errors() {
        let mut cells = Cells::default();
        assert!(cells.cache.is_empty());

        let cell_name_in = CellName::random_for_tests();

        assert!(matches!(
            cells.get(&cell_name_in, |_cell| Ok(())),
            Err(CellsError::CellNotFound { cell_name }) if cell_name == cell_name_in
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_free() {
        skip_if_not_root!("test_free");
        // Docker's seccomp security profile (https://docs.docker.com/engine/security/seccomp/) blocks clone
        skip_if_seccomp!("test_free");

        let _ = AURAED_RUNTIME.set(AuraedRuntime::default());

        let mut cells = Cells::default();
        assert!(cells.cache.is_empty());

        let cell_name = CellName::random_for_tests();
        let cell = CellSpec::new_for_tests();
        let _ = cells
            .allocate(cell_name.clone(), cell)
            .await
            .expect("failed to allocate");

        cells.free(&cell_name).await.expect("failed to free");
        assert!(cells.cache.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_free_missing_is_error() {
        let mut cells = Cells::default();
        assert!(cells.cache.is_empty());

        let cell_name_in = CellName::random_for_tests();

        assert!(matches!(
            cells.free(&cell_name_in).await,
            Err(CellsError::CellNotFound { cell_name }) if cell_name == cell_name_in
        ));
    }

    struct Graph {
        name: CellName,
        children: Vec<Self>,
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_cell_graph_triple_nested() {
        skip_if_not_root!("test_cell_graph_triple_nested");
        skip_if_seccomp!("test_cell_graph_triple_nested");

        let _ = AURAED_RUNTIME.set(AuraedRuntime::default());

        let mut cells = Cells::default();
        assert!(cells.cache.is_empty());

        // Create grandparent cell
        let grandparent_cell_name = CellName::random_for_tests();
        let grandparent_cell = CellSpec::new_for_tests();
        let _ = cells
            .allocate(grandparent_cell_name.clone(), grandparent_cell)
            .await
            .expect("failed to allocate");

        // Create parent cell
        let parent_cell_name =
            CellName::random_child_for_tests(&grandparent_cell_name);
        let parent_cell = CellSpec::new_for_tests();
        let _ = cells
            .allocate(parent_cell_name.clone(), parent_cell)
            .await
            .expect("failed to allocate");

        // Create child cell
        let child_cell_name =
            CellName::random_child_for_tests(&parent_cell_name);
        let child_cell = CellSpec::new_for_tests();
        let _ = cells
            .allocate(child_cell_name.clone(), child_cell)
            .await
            .expect("failed to allocate");

        fn cell_fn(cell: &Cell) -> Result<Graph> {
            Ok(Graph {
                name: cell.name().clone(),
                children: CellsCache::get_all(cell, cell_fn)
                    .expect("get all failed")
                    .into_iter()
                    .filter_map(|x| x.ok())
                    .collect(),
            })
        }

        let cells = cells.get_all(cell_fn).expect("failed to get all cells");

        assert_eq!(cells.len(), 1);
        let grandparent_cell = cells[0].as_ref().unwrap();
        assert_eq!(grandparent_cell.name, grandparent_cell_name);
        assert_eq!(grandparent_cell.children.len(), 1);

        let parent_cell = &grandparent_cell.children[0];
        assert_eq!(parent_cell.name, parent_cell_name);
        assert_eq!(parent_cell.children.len(), 1);

        let child_cell = &parent_cell.children[0];
        assert_eq!(child_cell.name, child_cell_name);
        assert_eq!(child_cell.children.len(), 0);
    }
}
