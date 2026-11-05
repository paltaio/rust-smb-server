//! CREATE request validation.

mod common;

use common::client::*;
use smb_server::ShareBackend as _;
use smb_server::ntstatus;
use smb_server::wire::header::Command;
use smb_server::wire::messages::{CreateContext, CreateRequest};
use tempfile::tempdir;

fn context(name: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut chain = Vec::new();
    CreateContext::encode_chain(
        &[CreateContext {
            name: name.to_vec(),
            data: data.to_vec(),
        }],
        &mut chain,
    )
    .unwrap();
    chain
}

#[tokio::test]
async fn malformed_creates_are_refused() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    let eas = local(td.path()).capabilities().extended_attributes;
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;

    // NameLength 7.
    let req = CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: RW,
        file_attributes: 0,
        share_access: SHARE_ALL,
        create_disposition: FILE_OPEN,
        create_options: 0,
        name_offset: 0x78,
        name_length: 7,
        create_contexts_offset: 0,
        create_contexts_length: 0,
        name: b"f\0.\0t\0x".to_vec(),
        create_contexts: vec![],
    };
    let mut body = Vec::new();
    req.write_to(&mut body).unwrap();
    assert_eq!(
        c.send(Command::Create, &body).await.0,
        ntstatus::STATUS_INVALID_PARAMETER
    );

    let cases: [(Create, u32); 8] = [
        (
            Create {
                name: "f.txt",
                access: 0,
                ..Create::default()
            },
            ntstatus::STATUS_ACCESS_DENIED,
        ),
        (
            Create {
                name: "f.txt",
                options: FILE_OPEN_BY_FILE_ID,
                ..Create::default()
            },
            ntstatus::STATUS_NOT_SUPPORTED,
        ),
        (
            Create {
                name: "f.txt",
                options: FILE_RESERVE_OPFILTER,
                ..Create::default()
            },
            ntstatus::STATUS_NOT_SUPPORTED,
        ),
        (
            Create {
                name: "d1",
                access: FILE_GENERIC_READ,
                disposition: FILE_OVERWRITE_IF,
                options: FILE_DIRECTORY_FILE,
                ..Create::default()
            },
            ntstatus::STATUS_INVALID_PARAMETER,
        ),
        (
            Create {
                name: "d2",
                access: FILE_GENERIC_READ,
                disposition: FILE_CREATE,
                options: FILE_DIRECTORY_FILE | FILE_NO_INTERMEDIATE_BUFFERING,
                ..Create::default()
            },
            ntstatus::STATUS_INVALID_PARAMETER,
        ),
        (
            Create {
                name: "ea.txt",
                disposition: FILE_CREATE,
                contexts: context(CreateContext::NAME_EXTA, &[0; 12]),
                ..Create::default()
            },
            // One entry with an empty name.
            if eas {
                ntstatus::STATUS_INVALID_EA_NAME
            } else {
                ntstatus::STATUS_EAS_NOT_SUPPORTED
            },
        ),
        (
            Create {
                name: "f.txt",
                contexts: context(CreateContext::NAME_TWRP, &[0; 8]),
                ..Create::default()
            },
            ntstatus::STATUS_OBJECT_NAME_NOT_FOUND,
        ),
        (
            Create {
                name: "ro-doc.txt",
                access: RW | DELETE,
                disposition: FILE_CREATE,
                options: FILE_DELETE_ON_CLOSE,
                attributes: FILE_ATTRIBUTE_READONLY,
                ..Create::default()
            },
            ntstatus::STATUS_CANNOT_DELETE,
        ),
    ];
    for (create, status) in cases {
        let name = create.name;
        assert_eq!(c.create(create).await.unwrap_err(), status, "{name}");
    }
    for name in ["d1", "d2", "ea.txt", "ro-doc.txt"] {
        assert!(!td.path().join(name).exists(), "{name} was created");
    }
    // Ignored options do not stop a directory open.
    let d = c
        .create(Create {
            name: "d3",
            access: FILE_GENERIC_READ,
            disposition: FILE_CREATE,
            options: FILE_DIRECTORY_FILE | 0x20,
            ..Create::default()
        })
        .await
        .unwrap();
    c.close(d.file_id).await;
}

#[tokio::test]
async fn created_file_gets_the_requested_attributes() {
    let td = tempdir().unwrap();
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;
    let resp = c
        .create(Create {
            name: "ro.txt",
            disposition: FILE_CREATE,
            attributes: FILE_ATTRIBUTE_READONLY | 0x2,
            ..Create::default()
        })
        .await
        .unwrap();
    assert_eq!(
        resp.file_attributes & FILE_ATTRIBUTE_READONLY,
        FILE_ATTRIBUTE_READONLY
    );
    // The creating open still writes.
    assert_eq!(c.write(resp.file_id, 0, b"x").await, Ok(1));
    c.close(resp.file_id).await;
    let perms = std::fs::metadata(td.path().join("ro.txt"))
        .unwrap()
        .permissions();
    assert!(perms.readonly());
}

#[tokio::test]
async fn file_ids_are_unique_within_a_session() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;
    let first_tree = c.tree_id;
    let a = c.open("f.txt", FILE_READ_DATA, SHARE_ALL).await.unwrap();
    c.tree_id = common::tree_connect(&mut c.s, "\\\\127.0.0.1\\share", c.session_id, 100).await;
    assert_ne!(c.tree_id, first_tree);
    let b = c.open("f.txt", FILE_READ_DATA, SHARE_ALL).await.unwrap();
    assert_ne!(a, b);
}

const FILE_SEQUENTIAL_ONLY: u32 = 0x0000_0004;
const FILE_NO_EA_KNOWLEDGE: u32 = 0x0000_0200;
const FILE_RANDOM_ACCESS: u32 = 0x0000_0800;

#[tokio::test]
async fn default_stream_suffixes_open_the_file_or_directory() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    std::fs::create_dir(td.path().join("d")).unwrap();
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;

    for name in ["f.txt::$DATA", "f.txt::$data"] {
        let f = c.open(name, FILE_READ_DATA, SHARE_ALL).await.unwrap();
        assert_eq!(c.read(f, 0, 16).await.unwrap(), b"data", "{name}");
        c.close(f).await;
    }
    let created = c
        .create(Create {
            name: "new.txt::$DATA",
            disposition: FILE_CREATE,
            ..Create::default()
        })
        .await
        .unwrap();
    assert_eq!(created.create_action, 2, "FILE_CREATED");
    c.close(created.file_id).await;
    assert!(td.path().join("new.txt").is_file());

    // A directory stream takes the options of a file open, and
    // FILE_NON_DIRECTORY_FILE does not stop it.
    let directories = [
        ("d::$INDEX_ALLOCATION", 0, FILE_OPEN),
        ("d:$I30:$INDEX_ALLOCATION", 0, FILE_OPEN),
        ("d::$INDEX_ALLOCATION", FILE_SEQUENTIAL_ONLY, FILE_OPEN),
        ("d::$INDEX_ALLOCATION", FILE_RANDOM_ACCESS, FILE_OPEN),
        ("d::$INDEX_ALLOCATION", FILE_NO_EA_KNOWLEDGE, FILE_OPEN),
        (
            "d::$INDEX_ALLOCATION",
            FILE_NON_DIRECTORY_FILE,
            FILE_OPEN_IF,
        ),
        ("::$INDEX_ALLOCATION", 0, FILE_OPEN),
    ];
    for (name, options, disposition) in directories {
        let dir = c
            .create(Create {
                name,
                access: FILE_GENERIC_READ,
                options,
                disposition,
                ..Create::default()
            })
            .await
            .unwrap_or_else(|status| panic!("{name} {options:#x}: {status:#x}"));
        assert_eq!(dir.create_action, 1, "FILE_OPENED");
        assert_ne!(dir.file_attributes & FILE_ATTRIBUTE_DIRECTORY, 0, "{name}");
        c.close(dir.file_id).await;
    }
    for (name, disposition) in [
        ("new::$INDEX_ALLOCATION", FILE_CREATE),
        ("new2::$INDEX_ALLOCATION", FILE_OVERWRITE_IF),
    ] {
        let dir = c
            .create(Create {
                name,
                access: FILE_GENERIC_READ,
                disposition,
                ..Create::default()
            })
            .await
            .unwrap();
        assert_eq!(dir.create_action, 2, "FILE_CREATED");
        c.close(dir.file_id).await;
    }
    assert!(td.path().join("new").is_dir());
    assert!(td.path().join("new2").is_dir());
}

#[tokio::test]
async fn default_stream_suffixes_follow_the_directory_rules() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    std::fs::create_dir(td.path().join("d")).unwrap();
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;

    let both = FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE;
    let cases = [
        (
            "d::$DATA",
            0,
            FILE_OPEN,
            ntstatus::STATUS_FILE_IS_A_DIRECTORY,
        ),
        (
            "::$DATA",
            0,
            FILE_OPEN,
            ntstatus::STATUS_FILE_IS_A_DIRECTORY,
        ),
        (
            ".::$DATA",
            0,
            FILE_OPEN,
            ntstatus::STATUS_FILE_IS_A_DIRECTORY,
        ),
        (
            "d::$DATA",
            FILE_DIRECTORY_FILE,
            FILE_OPEN,
            ntstatus::STATUS_NOT_A_DIRECTORY,
        ),
        (
            "f.txt::$DATA",
            FILE_DIRECTORY_FILE,
            FILE_OPEN,
            ntstatus::STATUS_NOT_A_DIRECTORY,
        ),
        (
            "f.txt::$DATA",
            both,
            FILE_OPEN,
            ntstatus::STATUS_INVALID_PARAMETER,
        ),
        (
            "f.txt::$DATA",
            FILE_DIRECTORY_FILE,
            FILE_OVERWRITE_IF,
            ntstatus::STATUS_INVALID_PARAMETER,
        ),
        (
            "f.txt::$DATA",
            FILE_DIRECTORY_FILE | FILE_SEQUENTIAL_ONLY,
            FILE_OPEN,
            ntstatus::STATUS_INVALID_PARAMETER,
        ),
        (
            "f.txt::$INDEX_ALLOCATION",
            0,
            FILE_OPEN,
            ntstatus::STATUS_NOT_A_DIRECTORY,
        ),
        (
            "f.txt::$INDEX_ALLOCATION",
            0,
            FILE_CREATE,
            ntstatus::STATUS_OBJECT_NAME_COLLISION,
        ),
        (
            "f.txt::$INDEX_ALLOCATION",
            0,
            FILE_OVERWRITE_IF,
            ntstatus::STATUS_NOT_A_DIRECTORY,
        ),
        (
            "d::$INDEX_ALLOCATION",
            0,
            FILE_OVERWRITE_IF,
            ntstatus::STATUS_OBJECT_NAME_COLLISION,
        ),
        (
            "d::$INDEX_ALLOCATION",
            0,
            FILE_SUPERSEDE,
            ntstatus::STATUS_OBJECT_NAME_COLLISION,
        ),
        (
            "d::$INDEX_ALLOCATION",
            0,
            FILE_OVERWRITE,
            ntstatus::STATUS_OBJECT_NAME_COLLISION,
        ),
        (
            "::$INDEX_ALLOCATION",
            0,
            FILE_OVERWRITE_IF,
            ntstatus::STATUS_ACCESS_DENIED,
        ),
        (
            "d::$INDEX_ALLOCATION",
            FILE_DIRECTORY_FILE,
            FILE_OVERWRITE_IF,
            ntstatus::STATUS_INVALID_PARAMETER,
        ),
        (
            "missing::$INDEX_ALLOCATION",
            0,
            FILE_OVERWRITE,
            ntstatus::STATUS_OBJECT_NAME_NOT_FOUND,
        ),
    ];
    for (name, options, disposition, status) in cases {
        let create = Create {
            name,
            access: FILE_GENERIC_READ,
            options,
            disposition,
            ..Create::default()
        };
        assert_eq!(
            c.create(create).await.unwrap_err(),
            status,
            "{name} {options:#x} {disposition}"
        );
    }
    assert!(td.path().join("f.txt").is_file());
    assert_eq!(std::fs::read(td.path().join("f.txt")).unwrap(), b"data");
    assert!(!td.path().join("missing").exists());
}

#[tokio::test]
async fn named_streams_are_refused_on_a_share_without_them() {
    let td = tempdir().unwrap();
    std::fs::write(td.path().join("f.txt"), b"data").unwrap();
    std::fs::create_dir(td.path().join("d")).unwrap();
    let share = smb_server::Share::new("share", local(td.path()))
        .public()
        .named_streams(false);
    let server = Server::start(smb_server::SmbServer::builder().share(share)).await;
    let mut c = server.client().await;

    for name in [
        "f.txt:s",
        "f.txt:s:$DATA",
        "f.txt:s:$INDEX_ALLOCATION",
        "d:s",
        ":s",
        "new.txt:s",
        "f.txt:",
        "f.txt::",
        "f.txt:s:$FOO",
        "f.txt:a:b:c",
        "d:s\\f.txt",
    ] {
        let create = Create {
            name,
            disposition: FILE_OPEN_IF,
            ..Create::default()
        };
        assert_eq!(
            c.create(create).await.unwrap_err(),
            ntstatus::STATUS_OBJECT_NAME_INVALID,
            "{name}"
        );
    }
    assert!(!td.path().join("new.txt").exists());
    assert_eq!(std::fs::read(td.path().join("f.txt")).unwrap(), b"data");
}

/// Opens the FIFO at `path` for reading and for writing without blocking,
/// and writes to it, so a thread stuck opening, reading or writing it
/// returns.
#[cfg(unix)]
fn release(path: &std::path::Path) {
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::OpenOptionsExt as _;
    let reader = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path);
    if let Ok(mut fifo) = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
    {
        let _ = fifo.write_all(b"x");
    }
    if let Ok(mut reader) = reader {
        let _ = reader.read(&mut [0; 64]);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn fifos_sockets_and_links_to_them_are_refused_at_once() {
    use smb_server::ShareBackend as _;
    use std::os::unix::fs::FileTypeExt as _;

    let td = tempdir().unwrap();
    let fifo = td.path().join("fifo");
    let path = std::ffi::CString::new(fifo.clone().into_os_string().into_encoded_bytes()).unwrap();
    // SAFETY: `path` is a NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o644) }, 0);
    let _socket = std::os::unix::net::UnixListener::bind(td.path().join("sock")).unwrap();
    std::os::unix::fs::symlink("fifo", td.path().join("to-fifo")).unwrap();
    let streams = local(td.path()).capabilities().named_streams;
    let server = Server::public(local(td.path())).await;
    let mut c = server.client().await;

    const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    for name in ["fifo", "sock", "to-fifo", "fifo:s"] {
        let expected = if name.contains(':') && !streams {
            ntstatus::STATUS_OBJECT_NAME_INVALID
        } else {
            ntstatus::STATUS_IO_REPARSE_TAG_NOT_HANDLED
        };
        for (access, disposition, options) in [
            (FILE_READ_DATA, FILE_OPEN, 0),
            (FILE_READ_ATTRIBUTES, FILE_OPEN, 0),
            (FILE_READ_ATTRIBUTES, FILE_OPEN, FILE_OPEN_REPARSE_POINT),
            (RW, FILE_OPEN, 0),
            (RW, FILE_CREATE, 0),
            (RW, FILE_OPEN_IF, 0),
            (RW, FILE_OVERWRITE, 0),
            (RW, FILE_OVERWRITE_IF, 0),
            (RW, FILE_SUPERSEDE, 0),
            (FILE_READ_DATA, FILE_OPEN, FILE_DIRECTORY_FILE),
            (FILE_READ_DATA, FILE_OPEN_IF, FILE_DIRECTORY_FILE),
            (RW, FILE_CREATE, FILE_DIRECTORY_FILE),
        ] {
            // A named stream is no directory, which the name already says.
            if name.contains(':') && options == FILE_DIRECTORY_FILE {
                continue;
            }
            let create = c.create(Create {
                name,
                access,
                disposition,
                options,
                ..Create::default()
            });
            let Ok(created) =
                tokio::time::timeout(std::time::Duration::from_secs(10), create).await
            else {
                release(&fifo);
                panic!("CREATE {name} {access:#x} {disposition} {options:#x} blocked");
            };
            assert_eq!(
                created.map(|r| r.file_id).err(),
                Some(expected),
                "{name} {access:#x} {disposition} {options:#x}"
            );
        }
    }
    assert!(
        std::fs::symlink_metadata(&fifo)
            .unwrap()
            .file_type()
            .is_fifo()
    );
}
