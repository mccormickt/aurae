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
use std::collections::HashMap;
use std::ffi::OsString;
use std::sync::Mutex;
use tracing::warn;
use walkdir::DirEntryExt;
use walkdir::WalkDir;

/// Cache that is used for looking up cgroup paths by inode number.
///
/// TODO (jeroensoeters) maybe change this to an LRU cache in the future? Also
/// we should think if inode wraparound is a potential issue. We could look at
/// how the Linux inode cache is implemented:
/// https://elixir.bootlin.com/linux/latest/source/fs/inode.c
#[derive(Debug)]
pub(crate) struct CgroupCache {
    root: OsString,
    cache: Mutex<HashMap<u64, OsString>>,
}

impl CgroupCache {
    pub fn new(root: OsString) -> Self {
        Self { root, cache: Mutex::new(HashMap::new()) }
    }

    pub fn get(&self, ino: u64) -> Option<OsString> {
        let cache = self.cache.lock().expect("Failed to lock cache");
        if let Some(path) = cache.get(&ino) {
            Some(path.clone())
        } else {
            self.refresh_cache();
            cache.get(&ino).cloned()
        }
    }

    fn refresh_cache(&self) {
        WalkDir::new(&self.root).into_iter().for_each(|res| match res {
            Ok(dir_entry) => {
                let mut cache =
                    self.cache.lock().expect("Failed to lock cache");
                _ = cache.insert(dir_entry.ino(), dir_entry.path().into());
            }
            Err(e) => {
                warn!("could not read from {:?}: {}", self.root, e);
            }
        });
    }
}

#[cfg(test)]
mod test {
    use std::fs;
    use std::fs::File;
    use std::os::unix::fs::DirEntryExt;

    use super::*;

    #[test]
    fn get_must_return_none_when_file_doesnt_exist() {
        let cache = CgroupCache::new(OsString::from("/tmp"));

        assert_eq!(cache.get(123), None);
    }

    #[test]
    fn get_must_return_file_for_ino() {
        let cache = CgroupCache::new(OsString::from("/tmp"));

        let file_name1 = uuid::Uuid::new_v4().to_string();
        let ino1 = create_file(&OsString::from(&file_name1));

        let file_name2 = uuid::Uuid::new_v4().to_string();
        let ino2 = create_file(&OsString::from(&file_name2));

        assert!(cache.get(ino1).is_some());
        assert!(
            cache
                .get(ino1)
                .expect("should not happen")
                .eq_ignore_ascii_case(format!("/tmp/{file_name1}"))
        );

        assert!(cache.get(ino2).is_some());
        assert!(
            cache
                .get(ino2)
                .expect("should not happen")
                .eq_ignore_ascii_case(format!("/tmp/{file_name2}"))
        );
    }

    fn create_file(file_name: &OsString) -> u64 {
        let _file = File::create(format!(
            "/tmp/{}",
            file_name
                .to_ascii_lowercase()
                .to_str()
                .expect("couldn't convert filename")
        ))
        .expect("couldn't create file");
        let dir_entry = fs::read_dir("/tmp")
            .expect("tmp dir entries")
            .find(|e| {
                println!("{:?}", e.as_ref().expect("").file_name());
                e.as_ref()
                    .expect("file")
                    .file_name()
                    .eq_ignore_ascii_case(file_name)
            })
            .expect("couldn't find file")
            .expect("dir entry");
        dir_entry.ino()
    }
}
