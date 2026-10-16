//! Request length fields larger than the received bytes fail to parse without
//! allocating more than `LIMIT` bytes.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use smb_server::wire::messages::{
    CreateRequest, FileId, IoctlRequest, NegotiateContext, QueryDirectoryRequest, QueryInfoRequest,
    ReadRequest, SessionSetupRequest, SetInfoRequest, TreeConnectRequest, WriteRequest,
};

/// Records the largest allocation made on the current thread while tracking.
struct LargestAlloc;

thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    static LARGEST: Cell<usize> = const { Cell::new(0) };
}

fn record(size: usize) {
    let _ = TRACKING.try_with(|tracking| {
        if tracking.get() {
            let _ = LARGEST.try_with(|largest| largest.set(largest.get().max(size)));
        }
    });
}

unsafe impl GlobalAlloc for LargestAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: LargestAlloc = LargestAlloc;

/// Declared length well past the bytes sent.
const HUGE: u32 = 0x1000_0000;
/// Allocation ceiling for parsing a request of a few hundred bytes.
const LIMIT: usize = 1024;

fn assert_rejected<T, E>(body: &[u8], parse: impl FnOnce(&[u8]) -> Result<T, E>) {
    LARGEST.with(|l| l.set(0));
    TRACKING.with(|t| t.set(true));
    let result = parse(body);
    TRACKING.with(|t| t.set(false));
    let largest = LARGEST.with(Cell::get);
    assert!(result.is_err(), "parse accepted a truncated buffer");
    assert!(
        largest <= LIMIT,
        "parsing a {}-byte request allocated {largest} bytes",
        body.len()
    );
}

#[test]
fn write_data_length() {
    let mut body = Vec::new();
    WriteRequest {
        structure_size: 49,
        data_offset: WriteRequest::STANDARD_DATA_OFFSET,
        length: HUGE,
        offset: 0,
        file_id: FileId::new(1, 1),
        channel: 0,
        remaining_bytes: 0,
        write_channel_info_offset: 0,
        write_channel_info_length: 0,
        flags: 0,
        data: vec![0; 4],
    }
    .write_to(&mut body)
    .unwrap();
    assert_rejected(&body, WriteRequest::parse);
}

fn create_request(name_length: u16, create_contexts_length: u32) -> Vec<u8> {
    let mut body = Vec::new();
    CreateRequest {
        structure_size: 57,
        security_flags: 0,
        requested_oplock_level: 0,
        impersonation_level: 2,
        smb_create_flags: 0,
        reserved: 0,
        desired_access: 0x0012_0089,
        file_attributes: 0,
        share_access: 7,
        create_disposition: 1,
        create_options: 0,
        name_offset: 0x78,
        name_length,
        create_contexts_offset: 0x80,
        create_contexts_length,
        name: vec![b'a', 0],
        create_contexts: vec![],
    }
    .write_to(&mut body)
    .unwrap();
    body
}

#[test]
fn create_name_and_context_lengths() {
    assert_rejected(&create_request(u16::MAX, 0), CreateRequest::parse);
    assert_rejected(&create_request(2, HUGE), CreateRequest::parse);
}

#[test]
fn set_info_buffer_length() {
    let mut body = Vec::new();
    SetInfoRequest {
        structure_size: 33,
        info_type: 1,
        file_information_class: 0x14,
        buffer_length: HUGE,
        buffer_offset: 0x60,
        reserved: 0,
        additional_information: 0,
        file_id: FileId::new(1, 1),
        buffer: vec![0; 8],
    }
    .write_to(&mut body)
    .unwrap();
    assert_rejected(&body, SetInfoRequest::parse);
}

#[test]
fn query_info_input_buffer_length() {
    let mut body = Vec::new();
    QueryInfoRequest {
        structure_size: 41,
        info_type: 1,
        file_information_class: 0x0F,
        output_buffer_length: 4096,
        input_buffer_offset: 0x68,
        reserved: 0,
        input_buffer_length: HUGE,
        additional_information: 0,
        flags: 0,
        file_id: FileId::new(1, 1),
        input_buffer: vec![0; 8],
    }
    .write_to(&mut body)
    .unwrap();
    assert_rejected(&body, QueryInfoRequest::parse);
}

#[test]
fn ioctl_input_count() {
    let mut body = Vec::new();
    IoctlRequest {
        structure_size: 57,
        reserved: 0,
        ctl_code: 0x0014_0204,
        file_id: FileId::any(),
        input_offset: 0x78,
        input_count: HUGE,
        max_input_response: 0,
        output_offset: 0,
        output_count: 0,
        max_output_response: 24,
        flags: IoctlRequest::FLAG_IS_FSCTL,
        reserved2: 0,
        input: vec![0; 24],
    }
    .write_to(&mut body)
    .unwrap();
    assert_rejected(&body, IoctlRequest::parse);
}

#[test]
fn tree_connect_path_length() {
    let mut body = Vec::new();
    TreeConnectRequest {
        structure_size: 9,
        flags: 0,
        path_offset: 0x48,
        path_length: u16::MAX,
        path: vec![b'\\', 0],
    }
    .write_to(&mut body)
    .unwrap();
    assert_rejected(&body, TreeConnectRequest::parse);
}

#[test]
fn session_setup_security_buffer_length() {
    let mut body = Vec::new();
    SessionSetupRequest {
        structure_size: 25,
        flags: 0,
        security_mode: 1,
        capabilities: 0,
        channel: 0,
        security_buffer_offset: 0x58,
        security_buffer_length: u16::MAX,
        previous_session_id: 0,
        security_buffer: vec![0x60, 0],
    }
    .write_to(&mut body)
    .unwrap();
    assert_rejected(&body, SessionSetupRequest::parse);
}

#[test]
fn query_directory_file_name_length() {
    let mut body = Vec::new();
    QueryDirectoryRequest {
        structure_size: 33,
        file_information_class: 0x25,
        flags: 0,
        file_index: 0,
        file_id: FileId::new(1, 1),
        file_name_offset: 0x60,
        file_name_length: u16::MAX,
        output_buffer_length: 4096,
        file_name: vec![b'*', 0],
    }
    .write_to(&mut body)
    .unwrap();
    assert_rejected(&body, QueryDirectoryRequest::parse);
}

#[test]
fn read_channel_info_length() {
    let mut body = Vec::new();
    ReadRequest {
        structure_size: 49,
        padding: 0x50,
        flags: 0,
        length: 64,
        offset: 0,
        file_id: FileId::new(1, 1),
        minimum_count: 0,
        channel: 0,
        remaining_bytes: 0,
        read_channel_info_offset: 0x70,
        read_channel_info_length: u16::MAX,
        buffer: vec![0],
    }
    .write_to(&mut body)
    .unwrap();
    assert_rejected(&body, ReadRequest::parse);
}

#[test]
fn negotiate_context_data_length_and_count() {
    let mut list = Vec::new();
    NegotiateContext::encode_list(
        &[NegotiateContext {
            context_type: NegotiateContext::TYPE_SIGNING,
            data_length: u16::MAX,
            reserved: 0,
            data: vec![0; 4],
        }],
        &mut list,
    )
    .unwrap();
    assert_rejected(&list, |b| NegotiateContext::parse_list(b, 1));
    assert_rejected(&list[..0], |b| NegotiateContext::parse_list(b, u16::MAX));
}
