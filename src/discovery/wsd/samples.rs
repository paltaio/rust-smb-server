//! Requests as Windows 11 sends them, and the device they are for.

use uuid::Uuid;

use crate::discovery::{Device, DeviceInfo};

/// The endpoint the samples address.
pub(super) const ENDPOINT: Uuid = Uuid::from_u128(0x3f2b_8c1e_7a4d_8e5f_9b6c_2d1e_0f3a_4b5c);

pub(super) fn device() -> Device {
    Device {
        endpoint: ENDPOINT,
        info: DeviceInfo {
            computer: "FILES".to_string(),
            workgroup: "WORKGROUP".to_string(),
            manufacturer: "smb-server".to_string(),
            model_name: "smb-server".to_string(),
            firmware_version: "0.7.0".to_string(),
        },
    }
}

pub(super) const PROBE: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" \
xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" \
xmlns:wsdp=\"http://schemas.xmlsoap.org/ws/2006/02/devprof\"><soap:Header>\
<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>\
<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>\
<wsa:MessageID>urn:uuid:9a1d6a3e-2f4b-4c5d-8e6f-7a8b9c0d1e2f</wsa:MessageID>\
</soap:Header><soap:Body><wsd:Probe><wsd:Types>wsdp:Device</wsd:Types></wsd:Probe>\
</soap:Body></soap:Envelope>";

pub(super) const PROBE_ID: &str = "urn:uuid:9a1d6a3e-2f4b-4c5d-8e6f-7a8b9c0d1e2f";

pub(super) const RESOLVE: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" \
xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><soap:Header>\
<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>\
<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve</wsa:Action>\
<wsa:MessageID>urn:uuid:4e5f6a7b-8c9d-4e0f-a1b2-c3d4e5f6a7b8</wsa:MessageID>\
</soap:Header><soap:Body><wsd:Resolve><wsa:EndpointReference>\
<wsa:Address>urn:uuid:3f2b8c1e-7a4d-8e5f-9b6c-2d1e0f3a4b5c</wsa:Address>\
</wsa:EndpointReference></wsd:Resolve></soap:Body></soap:Envelope>";

pub(super) const RESOLVE_ID: &str = "urn:uuid:4e5f6a7b-8c9d-4e0f-a1b2-c3d4e5f6a7b8";

pub(super) const GET: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" \
xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
xmlns:lms=\"http://schemas.microsoft.com/windows/lms/2007/08\"><soap:Header>\
<wsa:To>urn:uuid:3f2b8c1e-7a4d-8e5f-9b6c-2d1e0f3a4b5c</wsa:To>\
<wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</wsa:Action>\
<wsa:MessageID>urn:uuid:0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e</wsa:MessageID>\
<wsa:ReplyTo><wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous\
</wsa:Address></wsa:ReplyTo><wsa:From><wsa:Address>urn:uuid:5d6e7f8a-9b0c-4d1e-8f2a-3b4c5d6e7f8a\
</wsa:Address></wsa:From><lms:LargeMetadataSupport/></soap:Header><soap:Body/></soap:Envelope>";

pub(super) const GET_ID: &str = "urn:uuid:0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e";

/// [`GET`] in its HTTP request.
pub(super) fn get_request() -> Vec<u8> {
    format!(
        "POST /{ENDPOINT} HTTP/1.1\r\nCache-Control: no-cache\r\nConnection: Keep-Alive\r\n\
         Pragma: no-cache\r\nContent-Type: application/soap+xml\r\nUser-Agent: WSDAPI\r\n\
         Content-Length: {}\r\nHost: [fe80::1]:5357\r\n\r\n{GET}",
        GET.len()
    )
    .into_bytes()
}
