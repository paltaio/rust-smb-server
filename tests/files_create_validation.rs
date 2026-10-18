//! CREATE request validation.

mod common;

use common::client::*;
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
            ntstatus::STATUS_EAS_NOT_SUPPORTED,
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
