use std::collections::HashMap;
use std::sync::Mutex;

use crate::backend::{
    BackendCapabilities, DirEntry, FileInfo, FileTimes, Handle, OpenAction, OpenIntent,
    OpenOptions, ShareBackend,
};
use crate::error::{SmbError, SmbResult};
use crate::path::SmbPath;
use crate::stream::{StreamInfo, StreamName};
use async_trait::async_trait;
use bytes::Bytes;

/// In-memory backend for unit tests. Files and directories are keyed by
/// backslash-joined path. Clones share the same files. Files and
/// directories have named streams, unless made with
/// [`MemFsBackend::without_streams`].
#[derive(Clone)]
pub struct MemFsBackend {
    inner: std::sync::Arc<Mutex<MemInner>>,
}

/// A named stream: its id, which a rename keeps, its name as created or
/// renamed to, and its data.
struct MemStream {
    id: u64,
    name: String,
    data: Vec<u8>,
}

#[derive(Default)]
struct MemInner {
    files: HashMap<String, Vec<u8>>,
    /// All directories present (always includes "" for the root). Each
    /// directory is keyed by canonical path string.
    dirs: HashMap<String, ()>,
    /// Times set on entries: creation, access, write and change.
    times: HashMap<String, [u64; 4]>,
    /// Entries marked read-only.
    read_only: std::collections::HashSet<String>,
    /// The id of each entry that has had named streams; a rename moves it
    /// with the entry.
    ids: HashMap<String, u64>,
    next_id: u64,
    /// Named streams of each entry by id, in creation order.
    streams: HashMap<u64, Vec<MemStream>>,
    /// The backend reports no named streams.
    no_streams: bool,
    /// Handles opened and not yet closed.
    open_handles: usize,
}

impl MemInner {
    /// The id of the entry `key`, given one if it has none.
    fn id_of(&mut self, key: &str) -> u64 {
        if let Some(&id) = self.ids.get(key) {
            return id;
        }
        self.next_id += 1;
        self.ids.insert(key.to_string(), self.next_id);
        self.next_id
    }

    /// The name of the entry with the id `id`.
    fn path_of(&self, id: u64) -> Option<String> {
        self.ids
            .iter()
            .find(|&(_, &i)| i == id)
            .map(|(key, _)| key.clone())
    }

    /// Where the stream `name` of the entry `id` is in its list.
    fn stream_at(&self, id: u64, name: &str) -> Option<usize> {
        let name = name.to_lowercase();
        self.streams
            .get(&id)?
            .iter()
            .position(|s| s.name.to_lowercase() == name)
    }

    /// The data of the stream with the id `stream` of the entry `id`.
    fn stream_mut(&mut self, id: u64, stream: u64) -> SmbResult<&mut Vec<u8>> {
        self.streams
            .get_mut(&id)
            .and_then(|list| list.iter_mut().find(|s| s.id == stream))
            .map(|s| &mut s.data)
            .ok_or(SmbError::NotFound)
    }

    /// The streams of the entry `key`.
    fn streams_of(&self, key: &str) -> &[MemStream] {
        self.ids
            .get(key)
            .and_then(|id| self.streams.get(id))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Drops the entry `key`'s id and streams.
    fn forget(&mut self, key: &str) {
        if let Some(id) = self.ids.remove(key) {
            self.streams.remove(&id);
        }
    }

    /// Moves the ids of `from`, and of the entries below it, to `to`.
    fn move_ids(&mut self, from: &str, to: &str) {
        let below = format!("{from}\\");
        let moved: Vec<(String, String)> = self
            .ids
            .keys()
            .filter_map(|key| {
                if key == from {
                    Some((key.clone(), to.to_string()))
                } else {
                    key.strip_prefix(&below)
                        .map(|rest| (key.clone(), format!("{to}\\{rest}")))
                }
            })
            .collect();
        for (old, new) in moved {
            let id = self.ids.remove(&old).expect("listed");
            self.ids.insert(new, id);
        }
    }
}

impl Default for MemFsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MemFsBackend {
    pub fn new() -> Self {
        let mut inner = MemInner::default();
        inner.dirs.insert(String::new(), ());
        Self {
            inner: std::sync::Arc::new(Mutex::new(inner)),
        }
    }

    /// Handles opened and not yet closed.
    pub fn open_handles(&self) -> usize {
        self.inner.lock().unwrap().open_handles
    }

    pub fn with_file(self, path: &str, contents: &[u8]) -> Self {
        {
            let mut g = self.inner.lock().unwrap();
            g.files.insert(path.to_string(), contents.to_vec());
        }
        self
    }

    /// A backend that reports no named streams.
    pub fn without_streams(self) -> Self {
        self.inner.lock().unwrap().no_streams = true;
        self
    }

    /// The names of the named streams of `path`, in creation order.
    pub fn stream_names(&self, path: &str) -> Vec<String> {
        let g = self.inner.lock().unwrap();
        g.streams_of(path).iter().map(|s| s.name.clone()).collect()
    }

    /// The contents of the file `path`.
    pub fn contents(&self, path: &str) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().files.get(path).cloned()
    }
}

fn key(path: &SmbPath) -> String {
    path.display_backslash()
}

#[async_trait]
impl ShareBackend for MemFsBackend {
    async fn open(
        &self,
        path: &SmbPath,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        let k = key(path);
        let mut g = self.inner.lock().unwrap();
        let exists_file = g.files.contains_key(&k);
        let exists_dir = g.dirs.contains_key(&k);
        let parent_exists = path.parent().is_none_or(|p| g.dirs.contains_key(&key(&p)));
        if !exists_file && !exists_dir && !parent_exists {
            return Err(SmbError::PathNotFound);
        }

        if opts.directory {
            if exists_file {
                return Err(SmbError::NotADirectory);
            }
            let mut action = OpenAction::Opened;
            if !exists_dir {
                if matches!(opts.intent, OpenIntent::Create | OpenIntent::OpenOrCreate) {
                    g.dirs.insert(k.clone(), ());
                    action = OpenAction::Created;
                } else {
                    return Err(SmbError::NotFound);
                }
            } else if opts.intent == OpenIntent::Create {
                return Err(SmbError::Exists);
            }
            g.open_handles += 1;
            return Ok((Box::new(MemHandle::dir(self.inner.clone(), k)), action));
        }

        if exists_dir {
            if opts.non_directory {
                return Err(SmbError::IsDirectory);
            }
            return match opts.intent {
                OpenIntent::Open | OpenIntent::OpenOrCreate => {
                    g.open_handles += 1;
                    Ok((
                        Box::new(MemHandle::dir(self.inner.clone(), k)),
                        OpenAction::Opened,
                    ))
                }
                OpenIntent::Create => Err(SmbError::Exists),
                _ => Err(SmbError::IsDirectory),
            };
        }
        let action = match opts.intent {
            OpenIntent::Open => {
                if !exists_file {
                    return Err(SmbError::NotFound);
                }
                OpenAction::Opened
            }
            OpenIntent::Create => {
                if exists_file {
                    return Err(SmbError::Exists);
                }
                g.files.insert(k.clone(), Vec::new());
                OpenAction::Created
            }
            OpenIntent::OpenOrCreate => {
                g.files.entry(k.clone()).or_default();
                if exists_file {
                    OpenAction::Opened
                } else {
                    OpenAction::Created
                }
            }
            OpenIntent::Truncate => {
                if !exists_file {
                    return Err(SmbError::NotFound);
                }
                g.files.insert(k.clone(), Vec::new());
                OpenAction::Overwritten
            }
            OpenIntent::OverwriteOrCreate => {
                g.files.insert(k.clone(), Vec::new());
                if exists_file {
                    OpenAction::Overwritten
                } else {
                    OpenAction::Created
                }
            }
        };
        g.open_handles += 1;
        Ok((Box::new(MemHandle::file(self.inner.clone(), k)), action))
    }

    async fn unlink(&self, path: &SmbPath) -> SmbResult<()> {
        let k = key(path);
        let mut g = self.inner.lock().unwrap();
        if g.files.remove(&k).is_some() || g.dirs.remove(&k).is_some() {
            g.forget(&k);
            return Ok(());
        }
        Err(SmbError::NotFound)
    }

    async fn rename(&self, from: &SmbPath, to: &SmbPath, replace_if_exists: bool) -> SmbResult<()> {
        let kf = key(from);
        let kt = key(to);
        let mut g = self.inner.lock().unwrap();
        if kf != kt && (g.files.contains_key(&kt) || g.dirs.contains_key(&kt)) {
            if !replace_if_exists {
                return Err(SmbError::Exists);
            }
            if g.dirs.contains_key(&kt) {
                return Err(SmbError::AccessDenied);
            }
        }
        if let Some(data) = g.files.remove(&kf) {
            if kf != kt {
                g.forget(&kt);
            }
            g.move_ids(&kf, &kt);
            g.files.insert(kt, data);
            return Ok(());
        }
        if g.dirs.remove(&kf).is_some() {
            // Everything below the directory moves with it.
            let below = format!("{kf}\\");
            let moved = |key: &String| {
                key.strip_prefix(&below)
                    .map(|rest| (key.clone(), format!("{kt}\\{rest}")))
            };
            let files: Vec<_> = g.files.keys().filter_map(moved).collect();
            for (old, new) in files {
                let data = g.files.remove(&old).expect("listed");
                g.files.insert(new, data);
            }
            let dirs: Vec<_> = g.dirs.keys().filter_map(moved).collect();
            for (old, new) in dirs {
                g.dirs.remove(&old);
                g.dirs.insert(new, ());
            }
            g.move_ids(&kf, &kt);
            g.dirs.insert(kt, ());
            return Ok(());
        }
        Err(SmbError::NotFound)
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            is_read_only: false,
            case_sensitive: false,
            named_streams: !self.inner.lock().unwrap().no_streams,
        }
    }

    async fn open_stream(
        &self,
        file: Box<dyn Handle>,
        path: &SmbPath,
        stream: &StreamName,
        opts: OpenOptions,
    ) -> SmbResult<(Box<dyn Handle>, OpenAction)> {
        // Stream handles find their file by id, so they need no handle of
        // it.
        file.close().await?;
        let k = key(path);
        let mut g = self.inner.lock().unwrap();
        if !g.files.contains_key(&k) && !g.dirs.contains_key(&k) {
            return Err(SmbError::NotFound);
        }
        let id = g.id_of(&k);
        let at = g.stream_at(id, stream.as_str());
        g.next_id += 1;
        let new_id = g.next_id;
        let list = g.streams.entry(id).or_default();
        let (stream_id, action) = match (opts.intent, at) {
            (OpenIntent::Open | OpenIntent::Truncate, None) => return Err(SmbError::NotFound),
            (OpenIntent::Create, Some(_)) => return Err(SmbError::Exists),
            (OpenIntent::Open | OpenIntent::OpenOrCreate, Some(at)) => {
                (list[at].id, OpenAction::Opened)
            }
            (_, Some(at)) => {
                list[at].data.clear();
                (list[at].id, OpenAction::Overwritten)
            }
            (_, None) => {
                list.push(MemStream {
                    id: new_id,
                    name: stream.as_str().to_string(),
                    data: Vec::new(),
                });
                (new_id, OpenAction::Created)
            }
        };
        let is_dir = g.dirs.contains_key(&k);
        g.open_handles += 1;
        let handle = MemHandle {
            inner: self.inner.clone(),
            key: k,
            is_dir,
            stream: Some((id, stream_id)),
        };
        Ok((Box::new(handle), action))
    }

    async fn remove_stream(&self, path: &SmbPath, stream: &StreamName) -> SmbResult<()> {
        let mut g = self.inner.lock().unwrap();
        let id = *g.ids.get(&key(path)).ok_or(SmbError::NotFound)?;
        let at = g.stream_at(id, stream.as_str()).ok_or(SmbError::NotFound)?;
        g.streams.get_mut(&id).expect("listed").remove(at);
        Ok(())
    }

    async fn rename_stream(
        &self,
        path: &SmbPath,
        from: Option<&StreamName>,
        to: Option<&StreamName>,
        replace_if_exists: bool,
    ) -> SmbResult<()> {
        let k = key(path);
        let mut g = self.inner.lock().unwrap();
        if !g.files.contains_key(&k) && !g.dirs.contains_key(&k) {
            return Err(SmbError::NotFound);
        }
        let id = g.id_of(&k);
        let stream_id = |g: &MemInner, name: &StreamName| {
            g.stream_at(id, name.as_str())
                .map(|at| g.streams[&id][at].id)
        };
        let source = match from {
            Some(from) => Some(stream_id(&g, from).ok_or(SmbError::NotFound)?),
            None => None,
        };
        let target = to.and_then(|to| stream_id(&g, to));
        if (to.is_none() || target.is_some()) && !replace_if_exists {
            return Err(SmbError::Exists);
        }
        let data = match source {
            Some(source) => std::mem::take(g.stream_mut(id, source)?),
            None => std::mem::take(g.files.get_mut(&k).ok_or(SmbError::IsDirectory)?),
        };
        g.next_id += 1;
        let new_id = g.next_id;
        let list = g.streams.entry(id).or_default();
        list.retain(|s| Some(s.id) != target);
        match (source, to) {
            (Some(source), Some(to)) => {
                let stream = list.iter_mut().find(|s| s.id == source).expect("listed");
                stream.name = to.as_str().to_string();
                stream.data = data;
            }
            (None, Some(to)) => list.push(MemStream {
                id: new_id,
                name: to.as_str().to_string(),
                data,
            }),
            (Some(source), None) => {
                list.retain(|s| s.id != source);
                g.files.insert(k, data);
            }
            (None, None) => {
                g.files.insert(k, data);
            }
        }
        Ok(())
    }
}

pub struct MemHandle {
    inner: std::sync::Arc<Mutex<MemInner>>,
    key: String,
    is_dir: bool,
    /// The ids of the file and of the named stream the handle is on, so the
    /// handle follows renames of either.
    stream: Option<(u64, u64)>,
}

impl MemHandle {
    fn file(inner: std::sync::Arc<Mutex<MemInner>>, key: String) -> Self {
        Self {
            inner,
            key,
            is_dir: false,
            stream: None,
        }
    }

    fn dir(inner: std::sync::Arc<Mutex<MemInner>>, key: String) -> Self {
        Self {
            inner,
            key,
            is_dir: true,
            stream: None,
        }
    }

    /// The data the handle reads and writes: its stream's, or the file's.
    fn data<'a>(&self, g: &'a mut MemInner) -> SmbResult<&'a mut Vec<u8>> {
        match &self.stream {
            Some((id, stream)) => g.stream_mut(*id, *stream),
            None if self.is_dir => Err(SmbError::IsDirectory),
            None => g.files.get_mut(&self.key).ok_or(SmbError::NotFound),
        }
    }

    /// The name of the file the handle is on.
    fn path(&self, g: &MemInner) -> SmbResult<String> {
        match &self.stream {
            Some((id, _)) => g.path_of(*id).ok_or(SmbError::NotFound),
            None => Ok(self.key.clone()),
        }
    }
}

#[async_trait]
impl Handle for MemHandle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        let mut g = self.inner.lock().unwrap();
        let data = self.data(&mut g)?;
        let start = offset as usize;
        if start >= data.len() {
            return Ok(Bytes::new());
        }
        let end = (start + len as usize).min(data.len());
        Ok(Bytes::copy_from_slice(&data[start..end]))
    }

    async fn write(&self, offset: u64, data: &[u8]) -> SmbResult<u32> {
        let mut g = self.inner.lock().unwrap();
        let buf = self.data(&mut g)?;
        let needed = (offset as usize) + data.len();
        if buf.len() < needed {
            buf.resize(needed, 0);
        }
        buf[offset as usize..offset as usize + data.len()].copy_from_slice(data);
        Ok(data.len() as u32)
    }

    async fn flush(&self) -> SmbResult<()> {
        Ok(())
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        let mut g = self.inner.lock().unwrap();
        let size = if self.is_dir && self.stream.is_none() {
            0
        } else {
            self.data(&mut g)?.len() as u64
        };
        let key = self.path(&g)?;
        let name = key
            .rsplit_once('\\')
            .map(|(_, n)| n.to_string())
            .unwrap_or_else(|| key.clone());
        let [
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
        ] = g
            .times
            .get(&key)
            .copied()
            .unwrap_or([0x01D9_0000_0000_0000; 4]);
        Ok(FileInfo {
            name,
            end_of_file: size,
            allocation_size: size,
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
            is_directory: self.is_dir,
            read_only: g.read_only.contains(&key),
            file_index: 0,
        })
    }

    async fn set_times(&self, times: FileTimes) -> SmbResult<()> {
        let mut g = self.inner.lock().unwrap();
        let key = self.path(&g)?;
        let stored = g.times.entry(key).or_insert([0x01D9_0000_0000_0000; 4]);
        let wanted = [
            times.creation_time,
            times.last_access_time,
            times.last_write_time,
            times.change_time,
        ];
        for (slot, time) in stored.iter_mut().zip(wanted) {
            if let Some(time) = time {
                *slot = time;
            }
        }
        Ok(())
    }

    /// Keeps READONLY; ARCHIVE is accepted and not kept.
    async fn set_attributes(&self, attributes: u32) -> SmbResult<()> {
        const READONLY: u32 = 0x1;
        const ARCHIVE: u32 = 0x20;
        if attributes & !(READONLY | ARCHIVE) != 0 {
            return Err(SmbError::NotSupported);
        }
        let mut g = self.inner.lock().unwrap();
        let key = self.path(&g)?;
        if attributes & READONLY != 0 {
            g.read_only.insert(key);
        } else {
            g.read_only.remove(&key);
        }
        Ok(())
    }

    async fn truncate(&self, len: u64) -> SmbResult<()> {
        let mut g = self.inner.lock().unwrap();
        let buf = self.data(&mut g)?;
        buf.resize(len as usize, 0);
        Ok(())
    }

    async fn list_dir(&self, _pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        if !self.is_dir || self.stream.is_some() {
            return Err(SmbError::NotADirectory);
        }
        let g = self.inner.lock().unwrap();
        let prefix = if self.key.is_empty() {
            String::new()
        } else {
            format!("{}\\", self.key)
        };
        let mut entries = Vec::new();
        for (k, v) in g.files.iter() {
            if let Some(rest) = k.strip_prefix(&prefix)
                && !rest.contains('\\')
            {
                entries.push(DirEntry {
                    info: FileInfo {
                        name: rest.to_string(),
                        end_of_file: v.len() as u64,
                        allocation_size: v.len() as u64,
                        creation_time: 0x01D9_0000_0000_0000,
                        last_access_time: 0x01D9_0000_0000_0000,
                        last_write_time: 0x01D9_0000_0000_0000,
                        change_time: 0x01D9_0000_0000_0000,
                        is_directory: false,
                        read_only: false,
                        file_index: 0,
                    },
                });
            }
        }
        for k in g.dirs.keys() {
            if let Some(rest) = k.strip_prefix(&prefix)
                && !rest.is_empty()
                && !rest.contains('\\')
            {
                entries.push(DirEntry {
                    info: FileInfo {
                        name: rest.to_string(),
                        end_of_file: 0,
                        allocation_size: 0,
                        creation_time: 0x01D9_0000_0000_0000,
                        last_access_time: 0x01D9_0000_0000_0000,
                        last_write_time: 0x01D9_0000_0000_0000,
                        change_time: 0x01D9_0000_0000_0000,
                        is_directory: true,
                        read_only: false,
                        file_index: 0,
                    },
                });
            }
        }
        Ok(entries)
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        self.inner.lock().unwrap().open_handles -= 1;
        Ok(())
    }

    async fn streams(&self) -> SmbResult<Vec<StreamInfo>> {
        let g = self.inner.lock().unwrap();
        g.streams_of(&self.path(&g)?)
            .iter()
            .map(|s| {
                let size = s.data.len() as u64;
                Ok(StreamInfo::new(s.name.parse()?, size, size))
            })
            .collect()
    }
}
