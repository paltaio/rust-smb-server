//! A share on an S3 backend, and a client that drives it through the
//! dispatcher.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::task::JoinSet;

use super::fixture::{TestBucket, foreground, user_metadata};
use super::gateway::REGION;
use super::proxy::{Fault, Proxy, Reply, Seen};
use crate::backend::FILE_ATTRIBUTE_DIRECTORY;
use crate::ntstatus;
use crate::proto::header::{Command, SMB2_HEADER_LEN};
use crate::proto::messages::{
    CloseRequest, CreateRequest, CreateResponse, FileId, FlushRequest, QueryDirectoryRequest,
    QueryDirectoryResponse, ReadRequest, ReadResponse, SetInfoRequest, WriteRequest, WriteResponse,
};
use crate::s3::client::S3Client;
use crate::s3::encode::uri_encode;
use crate::server::ServerState;
use crate::tests::peer::{Peer, status};
use crate::utils::FILETIME_OFFSET;
use crate::{Handle, OpenOptions, S3Backend, S3BackendBuilder, Share, ShareBackend, SmbServer};

pub(super) const READ: u32 = 0x0012_0089;
pub(super) const DELETE: u32 = 0x0001_0000;
pub(super) const WRITE: u32 = 0x0012_0116;
pub(super) const WRITE_ATTRIBUTES: u32 = 0x0000_0100;

pub(super) const FILE_OPEN: u32 = 1;
pub(super) const FILE_CREATE: u32 = 2;
pub(super) const FILE_OPEN_IF: u32 = 3;
pub(super) const FILE_OVERWRITE: u32 = 4;
pub(super) const FILE_OVERWRITE_IF: u32 = 5;

pub(super) const FILE_DIRECTORY_FILE: u32 = 0x1;
pub(super) const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
pub(super) const FILE_DELETE_ON_CLOSE: u32 = 0x1000;

/// The FILETIME of `secs` and `nanos` after the Unix epoch.
pub(super) fn filetime(secs: u64, nanos: u32) -> u64 {
    FILETIME_OFFSET + secs * 10_000_000 + u64::from(nanos) / 100
}

/// Settings for a read-only backend of `bucket`, reached at `addr`.
pub(super) fn builder(bucket: &TestBucket, addr: SocketAddr) -> S3BackendBuilder {
    S3Backend::builder(format!("http://{addr}"), REGION, &bucket.name)
        .credentials(&bucket.gateway.access_key, &bucket.gateway.secret_key)
        .read_only()
}

/// Settings for a backend of `bucket` that keeps its changes in `cache`,
/// reached at `addr`.
pub(super) fn writable_builder(
    bucket: &TestBucket,
    addr: SocketAddr,
    cache: &Path,
) -> S3BackendBuilder {
    S3Backend::builder(format!("http://{addr}"), REGION, &bucket.name)
        .credentials(&bucket.gateway.access_key, &bucket.gateway.secret_key)
        .cache_dir(cache)
}

/// A read-only backend of `bucket`, reached directly.
pub(super) async fn backend(bucket: &TestBucket) -> S3Backend {
    builder(bucket, bucket.gateway.addr).build().await.unwrap()
}

/// Opens `name`, a path with `/` separators, on the backend itself.
pub(super) async fn open_handle(backend: &S3Backend, name: &str) -> Box<dyn Handle> {
    let (handle, _) = backend
        .open(&name.parse().unwrap(), OpenOptions::default())
        .await
        .unwrap();
    handle
}

/// Stores `body` under `key` with the user metadata `pairs`.
pub(super) async fn put_with(client: &S3Client, key: &str, body: &[u8], pairs: &[(&str, &str)]) {
    client
        .put_object(
            key,
            Bytes::copy_from_slice(body),
            &user_metadata(pairs),
            foreground(),
        )
        .await
        .unwrap();
}

/// Stores every key with its own name as the body, a few at a time.
pub(super) async fn put_all(client: &S3Client, keys: Vec<String>) {
    let mut running = JoinSet::new();
    for key in keys {
        if running.len() >= 16 {
            running.join_next().await.unwrap().unwrap();
        }
        let client = client.clone();
        running.spawn(async move {
            put_with(&client, &key, key.as_bytes(), &[]).await;
        });
    }
    while let Some(done) = running.join_next().await {
        done.unwrap();
    }
}

/// A backend of a fresh bucket reached through a proxy, a connection to a
/// share over it, and the proxy that sees every request the backend makes.
pub(super) struct Rig {
    pub(super) bucket: TestBucket,
    pub(super) proxy: Proxy,
    pub(super) backend: S3Backend,
    pub(super) smb: Smb,
    /// The cache directory of a writable backend.
    pub(super) cache: Option<tempfile::TempDir>,
}

impl Rig {
    pub(super) async fn new() -> Self {
        Self::with(|builder| builder).await
    }

    /// A rig whose backend has the settings `configure` makes.
    pub(super) async fn with(configure: impl FnOnce(S3BackendBuilder) -> S3BackendBuilder) -> Self {
        let bucket = TestBucket::new().await;
        let proxy = Proxy::start(bucket.gateway.addr).await;
        let backend = configure(builder(&bucket, proxy.addr))
            .build()
            .await
            .unwrap();
        let smb = Smb::new(backend.clone()).await;
        Rig {
            bucket,
            proxy,
            backend,
            smb,
            cache: None,
        }
    }

    /// A rig whose backend keeps its changes in a cache directory.
    pub(super) async fn writable() -> Self {
        Self::writable_with(|builder| builder).await
    }

    /// [`writable`](Self::writable) with the settings `configure` makes.
    pub(super) async fn writable_with(
        configure: impl FnOnce(S3BackendBuilder) -> S3BackendBuilder,
    ) -> Self {
        let bucket = TestBucket::new().await;
        let proxy = Proxy::start(bucket.gateway.addr).await;
        Rig::start(bucket, proxy, tempfile::tempdir().unwrap(), configure).await
    }

    /// The cache directory.
    pub(super) fn cache_dir(&self) -> &Path {
        self.cache.as_ref().expect("a writable rig").path()
    }

    /// Ends the backend and builds another on the same cache directory,
    /// as after a restart.
    pub(super) async fn restart(self) -> Self {
        self.restart_with(|builder| builder).await
    }

    /// [`restart`](Self::restart) with the settings `configure` makes.
    pub(super) async fn restart_with(
        self,
        configure: impl FnOnce(S3BackendBuilder) -> S3BackendBuilder,
    ) -> Self {
        let (bucket, proxy, cache) = self.stop().await;
        Rig::start(bucket, proxy, cache, configure).await
    }

    /// A rig for a bucket and a cache directory that exist already.
    pub(super) async fn start(
        bucket: TestBucket,
        proxy: Proxy,
        cache: tempfile::TempDir,
        configure: impl FnOnce(S3BackendBuilder) -> S3BackendBuilder,
    ) -> Self {
        let backend = configure(writable_builder(&bucket, proxy.addr, cache.path()))
            .build()
            .await
            .unwrap();
        let smb = Smb::new(backend.clone()).await;
        Rig {
            bucket,
            proxy,
            backend,
            smb,
            cache: Some(cache),
        }
    }

    /// Ends the backend, which releases the cache directory.
    pub(super) async fn stop(self) -> (TestBucket, Proxy, tempfile::TempDir) {
        let Rig {
            bucket,
            proxy,
            backend,
            mut smb,
            cache,
        } = self;
        smb.close_all().await;
        drop(smb);
        drop(backend);
        (bucket, proxy, cache.expect("a writable rig"))
    }

    /// The bucket, for putting objects in it without the backend knowing.
    pub(super) fn store(&self) -> &S3Client {
        &self.bucket.client
    }

    /// Hides the spelling `key`, as [`hide`] does.
    pub(super) fn hide(&self, key: &str) {
        hide(&self.proxy, &self.bucket.name, key);
    }
}

/// The body of a ListObjectsV2 answer with these objects, as keys and sizes,
/// and these common prefixes. Keys and prefixes are URL-encoded.
fn listing_xml(objects: &[(&str, u64)], prefixes: &[&str]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult>\
         <Name>b</Name><MaxKeys>1000</MaxKeys><EncodingType>url</EncodingType>\
         <IsTruncated>false</IsTruncated>",
    );
    for (key, size) in objects {
        xml.push_str(&format!(
            "<Contents><Key>{}</Key><LastModified>2024-01-02T03:04:05.000Z</LastModified>\
             <ETag>\"e\"</ETag><Size>{size}</Size></Contents>",
            uri_encode(key, true)
        ));
    }
    for prefix in prefixes {
        xml.push_str(&format!(
            "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
            uri_encode(prefix, true)
        ));
    }
    xml.push_str("</ListBucketResult>");
    xml
}

/// A listing answer with these keys and common prefixes, URL-encoded as the
/// client asks.
pub(super) fn listing_reply(objects: &[(&str, u64)], prefixes: &[&str]) -> Reply {
    Reply::new(200, listing_xml(objects, prefixes)).header("content-type", "application/xml")
}

/// Answers the listings of the directory with key prefix `prefix` (empty for
/// the bucket root) with `reply`.
pub(super) fn answer_listing(proxy: &Proxy, prefix: &str, reply: Reply) {
    let wanted = (!prefix.is_empty()).then(|| format!("prefix={}", uri_encode(prefix, false)));
    proxy.inject(
        move |seen| {
            seen.method == "GET"
                && seen.has_param("delimiter")
                && match &wanted {
                    Some(wanted) => seen.query().split('&').any(|param| param == wanted),
                    None => !seen.has_param("prefix"),
                }
        },
        Fault::Reply(reply),
        usize::MAX,
    );
}

/// Makes the proxy answer a lookup of `key` as a store that tells names
/// apart by case does when it has no such key: no object and nothing below
/// it. The gateway on a host whose file system folds case would find the
/// other spelling.
pub(super) fn hide(proxy: &Proxy, bucket: &str, key: &str) {
    let path = format!("/{bucket}/{}", uri_encode(key, true));
    proxy.inject(
        move |seen| seen.method == "HEAD" && seen.target == path,
        Fault::Reply(Reply::new(404, "")),
        usize::MAX,
    );
    let prefix = format!("prefix={}", uri_encode(&format!("{key}/"), false));
    proxy.inject(
        move |seen| {
            seen.method == "GET"
                && seen.has_param("max-keys")
                && seen.query().split('&').any(|param| param == prefix)
        },
        Fault::Reply(listing_reply(&[], &[])),
        usize::MAX,
    );
}

/// HEAD requests the proxy has seen.
pub(super) fn heads(proxy: &Proxy) -> usize {
    proxy.count(|seen| seen.method == "HEAD")
}

/// Listings of a whole directory: those with a delimiter.
pub(super) fn listings(proxy: &Proxy) -> usize {
    proxy.count(|seen| seen.method == "GET" && seen.has_param("delimiter"))
}

/// Whether `seen` is a read of object data: a GET that is not a listing.
pub(super) fn is_data_read(seen: &Seen) -> bool {
    seen.method == "GET" && !seen.has_param("list-type")
}

/// Reads of object data.
pub(super) fn reads(proxy: &Proxy) -> usize {
    proxy.count(is_data_read)
}

/// Every request the proxy has seen.
pub(super) fn requests(proxy: &Proxy) -> usize {
    proxy.seen().len()
}

/// Waits until `ready` holds. Panics with `what` if it does not within about
/// 5 s.
pub(super) async fn wait_until(what: &str, ready: impl Fn() -> bool) {
    wait_until_async(what, async || ready()).await;
}

/// [`wait_until`] for a condition that needs an await to check.
pub(super) async fn wait_until_async(what: &str, ready: impl AsyncFn() -> bool) {
    for _ in 0..500 {
        if ready().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("{what}");
}

/// Waits until the proxy has seen at least `count` requests that `matches`.
/// Panics if that takes more than about 5 s.
pub(super) async fn wait_for_requests(
    proxy: &Proxy,
    count: usize,
    matches: impl Fn(&Seen) -> bool,
) {
    wait_until(
        &format!("the proxy saw fewer than {count} requests"),
        || proxy.count(&matches) >= count,
    )
    .await;
}

/// What a CREATE answered.
#[derive(Debug, Clone)]
pub(super) struct Opened {
    pub(super) id: FileId,
    pub(super) action: u32,
    pub(super) size: u64,
    pub(super) allocation: u64,
    pub(super) attributes: u32,
    /// Creation, last access, last write and change times.
    pub(super) times: [u64; 4],
}

/// An entry of a directory listing.
#[derive(Debug, Clone)]
pub(super) struct Listed {
    pub(super) name: String,
    pub(super) size: u64,
    pub(super) attributes: u32,
    pub(super) times: [u64; 4],
}

impl Listed {
    pub(super) fn is_dir(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }
}

/// The names of `listed`, sorted.
pub(super) fn names(listed: &[Listed]) -> Vec<&str> {
    let mut names: Vec<&str> = listed.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    names
}

/// A CREATE request.
#[derive(Clone, Copy)]
pub(super) struct Spec {
    pub(super) access: u32,
    pub(super) disposition: u32,
    pub(super) options: u32,
}

impl Spec {
    pub(super) const FILE: Spec = Spec {
        access: READ,
        disposition: FILE_OPEN,
        options: FILE_NON_DIRECTORY_FILE,
    };
    pub(super) const DIR: Spec = Spec {
        access: READ,
        disposition: FILE_OPEN,
        options: FILE_DIRECTORY_FILE,
    };
    /// Neither flag: a file or a directory.
    pub(super) const ANY: Spec = Spec {
        access: READ,
        disposition: FILE_OPEN,
        options: 0,
    };

    pub(super) fn access(self, access: u32) -> Self {
        Spec { access, ..self }
    }

    pub(super) fn disposition(self, disposition: u32) -> Self {
        Spec {
            disposition,
            ..self
        }
    }

    pub(super) fn options(self, options: u32) -> Self {
        Spec { options, ..self }
    }

    fn body(self, name: &str) -> Vec<u8> {
        let units = crate::utils::utf16le(name);
        let mut padded = units.clone();
        padded.resize(padded.len().next_multiple_of(8), 0);
        let mut body = Vec::new();
        CreateRequest {
            structure_size: 57,
            security_flags: 0,
            requested_oplock_level: 0,
            impersonation_level: 2,
            smb_create_flags: 0,
            reserved: 0,
            desired_access: self.access,
            file_attributes: 0,
            share_access: 0x7,
            create_disposition: self.disposition,
            create_options: self.options,
            name_offset: 0x78,
            name_length: units.len() as u16,
            create_contexts_offset: 0,
            create_contexts_length: 0,
            name: padded,
            create_contexts: Vec::new(),
        }
        .write_to(&mut body)
        .expect("create");
        body
    }
}

/// One connection to the share `home` of a server over a backend.
pub(super) struct Smb {
    peer: Peer,
    state: Arc<ServerState>,
    /// The opens that are not closed.
    opened: Vec<FileId>,
}

impl Smb {
    pub(super) async fn new(backend: S3Backend) -> Self {
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .share(Share::new("home", backend).public())
            .build()
            .expect("build");
        let state = server.state();
        Smb {
            peer: Peer::new(&state, false).await,
            state,
            opened: Vec::new(),
        }
    }

    /// Closes every open that is left, as a connection that ends does.
    pub(super) async fn close_all(&mut self) {
        for id in std::mem::take(&mut self.opened) {
            self.close(id).await;
        }
    }

    async fn send(&mut self, command: Command, body: &[u8]) -> (u32, Vec<u8>) {
        let (_, reply) = self.peer.request(&self.state, command, body).await;
        (status(&reply), reply[SMB2_HEADER_LEN..].to_vec())
    }

    /// Opens `name`, a path with `\` separators. Fails with the status.
    pub(super) async fn create(&mut self, name: &str, spec: Spec) -> Result<Opened, u32> {
        match self.send(Command::Create, &spec.body(name)).await {
            (0, body) => {
                let reply = CreateResponse::parse(&body).expect("create response");
                self.opened.push(reply.file_id);
                Ok(Opened {
                    id: reply.file_id,
                    action: reply.create_action,
                    size: reply.end_of_file,
                    allocation: reply.allocation_size,
                    attributes: reply.file_attributes,
                    times: [
                        reply.creation_time,
                        reply.last_access_time,
                        reply.last_write_time,
                        reply.change_time,
                    ],
                })
            }
            (status, _) => Err(status),
        }
    }

    /// Opens the file `name`.
    pub(super) async fn open(&mut self, name: &str) -> Result<Opened, u32> {
        self.create(name, Spec::FILE).await
    }

    /// Opens the directory `name`.
    pub(super) async fn open_dir(&mut self, name: &str) -> Result<Opened, u32> {
        self.create(name, Spec::DIR).await
    }

    pub(super) async fn close(&mut self, id: FileId) {
        let mut body = Vec::new();
        CloseRequest {
            structure_size: 24,
            flags: 0,
            reserved: 0,
            file_id: id,
        }
        .write_to(&mut body)
        .expect("close");
        assert_eq!(self.send(Command::Close, &body).await.0, 0);
        self.opened.retain(|open| *open != id);
    }

    /// Reads up to `len` bytes at `offset`. An empty read at or past the
    /// end of the file fails with STATUS_END_OF_FILE.
    pub(super) async fn read(&mut self, id: FileId, offset: u64, len: u32) -> Result<Vec<u8>, u32> {
        let mut body = Vec::new();
        ReadRequest {
            structure_size: 49,
            padding: ReadResponse::STANDARD_DATA_OFFSET,
            flags: 0,
            length: len,
            offset,
            file_id: id,
            minimum_count: 0,
            channel: 0,
            remaining_bytes: 0,
            read_channel_info_offset: 0,
            read_channel_info_length: 0,
            buffer: vec![0],
        }
        .write_to(&mut body)
        .expect("read");
        match self.send(Command::Read, &body).await {
            (0, body) => Ok(ReadResponse::parse(&body).expect("read response").data),
            (status, _) => Err(status),
        }
    }

    /// The whole file `name`, read in pieces of `piece` bytes.
    pub(super) async fn contents(&mut self, name: &str, piece: u32) -> Vec<u8> {
        let file = self.open(name).await.expect("open");
        let mut data = Vec::new();
        loop {
            match self.read(file.id, data.len() as u64, piece).await {
                Ok(chunk) => data.extend_from_slice(&chunk),
                Err(status) if status == ntstatus::STATUS_END_OF_FILE => break,
                Err(status) => panic!("read {name}: {status:#x}"),
            }
        }
        self.close(file.id).await;
        data
    }

    /// The entries of the directory `dir` that match `pattern`, without `.`
    /// and `..`.
    pub(super) async fn list(&mut self, dir: FileId, pattern: &str) -> Vec<Listed> {
        match self.try_list(dir, pattern).await {
            Ok(listed) => listed,
            Err(status) => panic!("query directory: {status:#x}"),
        }
    }

    /// [`list`](Self::list), failing with the status of a query that fails.
    pub(super) async fn try_list(
        &mut self,
        dir: FileId,
        pattern: &str,
    ) -> Result<Vec<Listed>, u32> {
        let mut out = Vec::new();
        let mut flags = QueryDirectoryRequest::FLAG_RESTART_SCANS;
        loop {
            let units = crate::utils::utf16le(pattern);
            let mut body = Vec::new();
            QueryDirectoryRequest {
                structure_size: 33,
                file_information_class: 0x25,
                flags,
                file_index: 0,
                file_id: dir,
                file_name_offset: 0x60,
                file_name_length: units.len() as u16,
                output_buffer_length: 65536,
                file_name: units,
            }
            .write_to(&mut body)
            .expect("query directory");
            flags = 0;
            let (code, reply) = self.send(Command::QueryDirectory, &body).await;
            if code == ntstatus::STATUS_NO_MORE_FILES || code == ntstatus::STATUS_NO_SUCH_FILE {
                return Ok(out);
            }
            if code != 0 {
                return Err(code);
            }
            let buffer = QueryDirectoryResponse::parse(&reply)
                .expect("listing")
                .buffer;
            let mut at = 0;
            loop {
                let u32_at = |at: usize| u32::from_le_bytes(buffer[at..at + 4].try_into().unwrap());
                let u64_at = |at: usize| u64::from_le_bytes(buffer[at..at + 8].try_into().unwrap());
                let name_len = u32_at(at + 60) as usize;
                let units: Vec<u16> = buffer[at + 104..at + 104 + name_len]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let name = String::from_utf16(&units).unwrap();
                if name != "." && name != ".." {
                    out.push(Listed {
                        name,
                        size: u64_at(at + 40),
                        attributes: u32_at(at + 56),
                        times: [
                            u64_at(at + 8),
                            u64_at(at + 16),
                            u64_at(at + 24),
                            u64_at(at + 32),
                        ],
                    });
                }
                let next = u32_at(at) as usize;
                if next == 0 {
                    break;
                }
                at += next;
            }
        }
    }

    /// Writes `data` at `offset` of the open `id`. Returns the count written.
    pub(super) async fn write(&mut self, id: FileId, offset: u64, data: &[u8]) -> Result<u32, u32> {
        let mut body = Vec::new();
        WriteRequest {
            structure_size: 49,
            data_offset: WriteRequest::STANDARD_DATA_OFFSET,
            length: data.len() as u32,
            offset,
            file_id: id,
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: 0,
            data: data.to_vec(),
        }
        .write_to(&mut body)
        .expect("write");
        match self.send(Command::Write, &body).await {
            (0, body) => Ok(WriteResponse::parse(&body).expect("write response").count),
            (status, _) => Err(status),
        }
    }

    /// Flushes the open `id`. Returns the status.
    pub(super) async fn flush(&mut self, id: FileId) -> u32 {
        let mut body = Vec::new();
        FlushRequest::new(id.persistent, id.volatile)
            .write_to(&mut body)
            .expect("flush");
        self.send(Command::Flush, &body).await.0
    }

    /// Sets the length of the open `id`. Returns the status.
    pub(super) async fn set_size(&mut self, id: FileId, len: u64) -> u32 {
        self.set_info(id, 20, len.to_le_bytes().to_vec()).await
    }

    /// Sets the creation, access, write and change time of the open `id`, as
    /// FileBasicInformation takes them (0 leaves a time alone), and its
    /// attributes (0 leaves them alone). Returns the status.
    pub(super) async fn set_basic(&mut self, id: FileId, times: [i64; 4], attributes: u32) -> u32 {
        let mut buffer = Vec::new();
        for time in times {
            buffer.extend_from_slice(&time.to_le_bytes());
        }
        buffer.extend_from_slice(&attributes.to_le_bytes());
        buffer.extend_from_slice(&[0; 4]);
        self.set_info(id, 4, buffer).await
    }

    /// Renames the open `id` to `to`. Returns the status.
    pub(super) async fn rename(&mut self, id: FileId, to: &str) -> u32 {
        let target = crate::utils::utf16le(to);
        let mut buffer = vec![0u8; 16];
        buffer.extend_from_slice(&(target.len() as u32).to_le_bytes());
        buffer.extend_from_slice(&target);
        self.set_info(id, 10, buffer).await
    }

    /// Marks the open `id` for deletion. Returns the status.
    pub(super) async fn set_delete(&mut self, id: FileId) -> u32 {
        self.set_info(id, 13, vec![1]).await
    }

    async fn set_info(&mut self, id: FileId, class: u8, buffer: Vec<u8>) -> u32 {
        let mut body = Vec::new();
        SetInfoRequest {
            structure_size: 33,
            info_type: 1,
            file_information_class: class,
            buffer_length: buffer.len() as u32,
            buffer_offset: 0x60,
            reserved: 0,
            additional_information: 0,
            file_id: id,
            buffer,
        }
        .write_to(&mut body)
        .expect("set info");
        self.send(Command::SetInfo, &body).await.0
    }
}
