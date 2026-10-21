//! The srvsvc calls that list shares (MS-SRVS 3.1.4.8, 3.1.4.10,
//! 3.1.4.17): request decoding, the answers, and their NDR encoding. Every
//! other operation faults with nca_op_rng_error.

use super::association::Fault;
use super::ndr::{NdrReader, NdrWriter, string_len};
use super::pdu::NCA_OP_RNG_ERROR;
use crate::server::{Caller, ServerState};

pub(crate) const OPNUM_SHARE_ENUM: u16 = 15;
pub(crate) const OPNUM_SHARE_GET_INFO: u16 = 16;
pub(crate) const OPNUM_SERVER_GET_INFO: u16 = 21;

/// A stub that does not decode (MS-RPCE 3.1.3.5.2, RPC_X_BAD_STUB_DATA).
const BAD_STUB_DATA: u32 = 0x0000_06F7;

// Share types (MS-SRVS 2.2.2.4).
const STYPE_DISKTREE: u32 = 0;
const STYPE_IPC_SPECIAL: u32 = 0x8000_0003;

// NET_API_STATUS values (MS-SRVS 3.1.4.8, 3.1.4.10, MS-ERREF 2.2).
const NERR_SUCCESS: u32 = 0;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INVALID_LEVEL: u32 = 124;
const ERROR_MORE_DATA: u32 = 234;
const NERR_NET_NAME_NOT_FOUND: u32 = 2310;

/// PreferedMaximumLength asking for every entry (MS-SRVS 2.2.2.2).
const MAX_PREFERRED_LENGTH: u32 = u32::MAX;

/// SERVER_INFO values: PLATFORM_ID_NT, Windows 10 and later, and
/// SV_TYPE_WORKSTATION | SV_TYPE_SERVER | SV_TYPE_NT | SV_TYPE_SERVER_NT
/// (MS-SRVS 2.2.2.6, 2.2.2.7).
const PLATFORM_ID_NT: u32 = 500;
const VERSION_MAJOR: u32 = 10;
const VERSION_MINOR: u32 = 0;
const SERVER_TYPE: u32 = 0x0000_9003;

/// Levels with an arm in SHARE_ENUM_UNION: those of MS-SRVS 2.2.3.5, and
/// 1004 to 1501, which Samba's IDL adds and its clients send. Any other
/// level is sent with no arm, as the [default] arm of Samba's IDL does.
const ENUM_ARMS: [u32; 11] = [0, 1, 2, 501, 502, 503, 1004, 1005, 1006, 1007, 1501];
/// Levels with an arm in SHARE_INFO (MS-SRVS 2.2.3.6).
const SHARE_INFO_ARMS: [u32; 10] = [0, 1, 2, 501, 502, 503, 1004, 1005, 1006, 1501];
/// Levels with an arm in SERVER_INFO (MS-SRVS 2.2.3.7).
const SERVER_INFO_ARMS: [u32; 51] = [
    100, 101, 102, 103, 502, 503, 599, 1005, 1107, 1010, 1016, 1017, 1018, 1501, 1502, 1503, 1506,
    1510, 1511, 1512, 1513, 1514, 1515, 1516, 1518, 1523, 1528, 1529, 1530, 1533, 1534, 1535, 1536,
    1538, 1539, 1540, 1541, 1542, 1543, 1544, 1545, 1546, 1547, 1548, 1549, 1550, 1552, 1553, 1554,
    1555, 1556,
];
/// Levels that carry paths, security descriptors or server settings,
/// which Windows gives administrators only; no session here is one.
const DENIED_SHARE_LEVELS: [u32; 3] = [2, 502, 503];
const DENIED_SERVER_LEVELS: [u32; 3] = [102, 502, 503];

/// One share as a list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListedShare {
    pub name: String,
    pub kind: u32,
    pub remark: String,
}

impl ListedShare {
    fn ipc() -> Self {
        Self {
            name: "IPC$".to_string(),
            kind: STYPE_IPC_SPECIAL,
            remark: "Remote IPC".to_string(),
        }
    }
}

/// A decoded request.
pub(crate) enum Request {
    ShareEnum(ShareEnum),
    ShareGetInfo(ShareGetInfo),
    ServerGetInfo(ServerGetInfo),
}

/// Decodes the request stub of the operation `opnum`. Unknown operations
/// fault with nca_op_rng_error, stubs that do not decode with 0x6F7.
pub(crate) fn decode(opnum: u16, stub: &[u8]) -> Result<Request, Fault> {
    let request = match opnum {
        OPNUM_SHARE_ENUM => ShareEnum::decode(stub).map(Request::ShareEnum),
        OPNUM_SHARE_GET_INFO => ShareGetInfo::decode(stub).map(Request::ShareGetInfo),
        OPNUM_SERVER_GET_INFO => ServerGetInfo::decode(stub).map(Request::ServerGetInfo),
        _ => {
            return Err(Fault {
                status: NCA_OP_RNG_ERROR,
                did_not_execute: true,
            });
        }
    };
    request.ok_or(Fault {
        status: BAD_STUB_DATA,
        did_not_execute: false,
    })
}

/// Runs the operation `opnum` for `caller` and returns the response stub.
/// The shares are read at the time of the call, and only as far as the
/// call needs them.
pub(crate) async fn serve(
    server: &ServerState,
    caller: &Caller,
    opnum: u16,
    stub: &[u8],
) -> Result<Vec<u8>, Fault> {
    Ok(match decode(opnum, stub)? {
        Request::ShareEnum(request) => request.answer(&listed_shares(server, caller).await),
        Request::ShareGetInfo(request) => {
            let share = match request.lookup() {
                Some(name) => find_share(server, caller, name).await,
                None => None,
            };
            request.answer(share.as_ref())
        }
        Request::ServerGetInfo(request) => request.answer(&server.config.netbios_name),
    })
}

/// The shares `caller` sees when it lists them: those its TREE_CONNECT
/// would be granted, unless left out of listings, in the order they were
/// added, then IPC$.
pub(crate) async fn listed_shares(server: &ServerState, caller: &Caller) -> Vec<ListedShare> {
    let mut shares = Vec::new();
    for share in server.shares.all_in_order().await {
        if share.listed
            && server
                .admits(&share, &*share.acl.read().await, caller)
                .is_some()
        {
            shares.push(ListedShare {
                name: share.name.clone(),
                kind: STYPE_DISKTREE,
                remark: share.remark.clone(),
            });
        }
    }
    shares.push(ListedShare::ipc());
    shares
}

/// The share named `name`, matched ignoring ASCII case as TREE_CONNECT
/// matches it, when `caller` may connect to it, listed or not. IPC$ is
/// always found.
pub(crate) async fn find_share(
    server: &ServerState,
    caller: &Caller,
    name: &str,
) -> Option<ListedShare> {
    if name.eq_ignore_ascii_case("IPC$") {
        return Some(ListedShare::ipc());
    }
    let share = server.find_share(name).await?;
    server.admits(&share, &*share.acl.read().await, caller)?;
    Some(ListedShare {
        name: share.name.clone(),
        kind: STYPE_DISKTREE,
        remark: share.remark.clone(),
    })
}

/// A fixed server and share list, for answering without a server.
#[cfg(any(test, fuzzing))]
pub(crate) struct ShareView {
    pub server_name: String,
    pub shares: Vec<ListedShare>,
}

/// [`serve`] against `view`: the caller sees its shares, and GetInfo finds
/// them by name.
#[cfg(any(test, fuzzing))]
pub(crate) fn call(opnum: u16, stub: &[u8], view: &ShareView) -> Result<Vec<u8>, Fault> {
    Ok(match decode(opnum, stub)? {
        Request::ShareEnum(request) => request.answer(&view.shares),
        Request::ShareGetInfo(request) => {
            let share = request.lookup().and_then(|name| {
                view.shares
                    .iter()
                    .find(|share| share.name.eq_ignore_ascii_case(name))
            });
            request.answer(share)
        }
        Request::ServerGetInfo(request) => request.answer(&view.server_name),
    })
}

/// Skips ServerName, a unique pointer to a string. Its value is not used.
fn skip_server_name(r: &mut NdrReader<'_>) -> Option<()> {
    if r.pointer()? {
        r.string()?;
    }
    Some(())
}

/// NetrShareEnum (opnum 15).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ShareEnum {
    level: u32,
    /// The request's container pointer was not NULL.
    container: bool,
    preferred_max: u32,
    resume: Option<u32>,
}

impl ShareEnum {
    /// The container a client sends is empty: its Buffer must be NULL.
    fn decode(stub: &[u8]) -> Option<Self> {
        let mut r = NdrReader::new(stub);
        skip_server_name(&mut r)?;
        let level = r.u32()?;
        if r.u32()? != level {
            return None;
        }
        let container = ENUM_ARMS.contains(&level) && r.pointer()?;
        if container {
            let _entries_read = r.u32()?;
            if r.pointer()? {
                return None;
            }
        }
        let preferred_max = r.u32()?;
        let resume = if r.pointer()? { Some(r.u32()?) } else { None };
        Some(Self {
            level,
            container,
            preferred_max,
            resume,
        })
    }

    /// MS-SRVS 3.1.4.8 over `shares`. The resume handle is the index of the
    /// next share to send. Entries are sent while their NDR size fits
    /// PreferedMaximumLength, and at least one. Levels other than 0, 1 and
    /// 501 send back the container the client sent, still empty.
    fn answer(&self, shares: &[ListedShare]) -> Vec<u8> {
        let mut w = NdrWriter::new();
        w.u32(self.level);
        w.u32(self.level);
        let (total, resume, status) = match self.level {
            0 | 1 | 501 => {
                let start = self.resume.map_or(0, |at| at as usize).min(shares.len());
                let rest = &shares[start..];
                let sent = self.fits(rest);
                write_container(&mut w, self.level, &rest[..sent]);
                if sent < rest.len() {
                    (rest.len(), (start + sent) as u32, ERROR_MORE_DATA)
                } else {
                    (rest.len(), 0, NERR_SUCCESS)
                }
            }
            level => {
                if ENUM_ARMS.contains(&level) {
                    w.pointer(self.container);
                    if self.container {
                        w.u32(0);
                        w.pointer(false);
                    }
                }
                let status = if DENIED_SHARE_LEVELS.contains(&level) {
                    ERROR_ACCESS_DENIED
                } else {
                    ERROR_INVALID_LEVEL
                };
                (0, self.resume.unwrap_or(0), status)
            }
        };
        w.u32(u32::try_from(total).unwrap_or(u32::MAX));
        w.pointer(self.resume.is_some());
        if self.resume.is_some() {
            w.u32(resume);
        }
        w.u32(status);
        w.finish()
    }

    /// How many of `shares` to send.
    fn fits(&self, shares: &[ListedShare]) -> usize {
        if self.preferred_max == MAX_PREFERRED_LENGTH {
            return shares.len();
        }
        let budget = self.preferred_max as usize;
        let mut used = 0;
        let count = shares
            .iter()
            .take_while(|share| {
                used += entry_len(self.level, share);
                used <= budget
            })
            .count();
        count.max(1).min(shares.len())
    }
}

/// NDR bytes one entry of `level` takes: its fixed part and its strings.
fn entry_len(level: u32, share: &ListedShare) -> usize {
    let name = string_len(&share.name);
    match level {
        0 => 4 + name,
        1 => 12 + name + string_len(&share.remark),
        _ => 16 + name + string_len(&share.remark),
    }
}

/// A SHARE_INFO_0, _1 or _501 container holding `shares`: the fixed part
/// of every entry, then their strings (C706 14.3.12.3).
fn write_container(w: &mut NdrWriter, level: u32, shares: &[ListedShare]) {
    let count = u32::try_from(shares.len()).unwrap_or(u32::MAX);
    w.pointer(true);
    w.u32(count);
    w.pointer(!shares.is_empty());
    if shares.is_empty() {
        return;
    }
    w.u32(count);
    for share in shares {
        write_fixed(w, level, share);
    }
    for share in shares {
        write_strings(w, level, share);
    }
}

/// The fixed part of a SHARE_INFO_0, _1 or _501 (MS-SRVS 2.2.4.22,
/// 2.2.4.23, 2.2.4.25). Flags (shi501_flags) are 0: manual caching.
fn write_fixed(w: &mut NdrWriter, level: u32, share: &ListedShare) {
    w.pointer(true);
    if level == 0 {
        return;
    }
    w.u32(share.kind);
    w.pointer(true);
    if level == 501 {
        w.u32(0);
    }
}

fn write_strings(w: &mut NdrWriter, level: u32, share: &ListedShare) {
    w.string(&share.name);
    if level != 0 {
        w.string(&share.remark);
    }
}

/// NetrShareGetInfo (opnum 16).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ShareGetInfo {
    name: String,
    level: u32,
}

impl ShareGetInfo {
    fn decode(stub: &[u8]) -> Option<Self> {
        let mut r = NdrReader::new(stub);
        skip_server_name(&mut r)?;
        let name = String::from_utf16_lossy(&r.string()?);
        let level = r.u32()?;
        Some(Self { name, level })
    }

    /// The share to look up, when the answer depends on it: a name is
    /// given and the level is one the server answers.
    fn lookup(&self) -> Option<&str> {
        (!self.name.is_empty() && matches!(self.level, 0 | 1 | 501 | 1005))
            .then_some(self.name.as_str())
    }

    /// MS-SRVS 3.1.4.10 with `share`, what [`ShareGetInfo::lookup`] found.
    /// A share the caller may not connect to is not found.
    fn answer(&self, share: Option<&ListedShare>) -> Vec<u8> {
        let mut w = NdrWriter::new();
        w.u32(self.level);
        let level = self.level;
        let status = if self.name.is_empty() {
            ERROR_INVALID_PARAMETER
        } else if !matches!(level, 0 | 1 | 2 | 501 | 502 | 503 | 1005) {
            ERROR_INVALID_LEVEL
        } else if DENIED_SHARE_LEVELS.contains(&level) {
            ERROR_ACCESS_DENIED
        } else if let Some(share) = share {
            w.pointer(true);
            if level == 1005 {
                w.u32(0);
            } else {
                write_fixed(&mut w, level, share);
                write_strings(&mut w, level, share);
            }
            w.u32(NERR_SUCCESS);
            return w.finish();
        } else {
            NERR_NET_NAME_NOT_FOUND
        };
        if SHARE_INFO_ARMS.contains(&level) {
            w.pointer(false);
        }
        w.u32(status);
        w.finish()
    }
}

/// NetrServerGetInfo (opnum 21).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ServerGetInfo {
    level: u32,
}

impl ServerGetInfo {
    fn decode(stub: &[u8]) -> Option<Self> {
        let mut r = NdrReader::new(stub);
        skip_server_name(&mut r)?;
        Some(Self { level: r.u32()? })
    }

    /// MS-SRVS 3.1.4.17: SERVER_INFO_100 or _101 with `server_name` and an
    /// empty comment.
    fn answer(&self, server_name: &str) -> Vec<u8> {
        let mut w = NdrWriter::new();
        w.u32(self.level);
        let status = match self.level {
            100 | 101 => {
                w.pointer(true);
                w.u32(PLATFORM_ID_NT);
                w.pointer(true);
                if self.level == 101 {
                    w.u32(VERSION_MAJOR);
                    w.u32(VERSION_MINOR);
                    w.u32(SERVER_TYPE);
                    w.pointer(true);
                }
                w.string(server_name);
                if self.level == 101 {
                    w.string("");
                }
                w.u32(NERR_SUCCESS);
                return w.finish();
            }
            level if DENIED_SERVER_LEVELS.contains(&level) => ERROR_ACCESS_DENIED,
            _ => ERROR_INVALID_LEVEL,
        };
        if SERVER_INFO_ARMS.contains(&self.level) {
            w.pointer(false);
        }
        w.u32(status);
        w.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::auth::ntlm::Identity;
    use crate::rpc::pdu::tests::unhex;
    use crate::tests::memfs::MemFsBackend;
    use crate::{Access, Share, SmbServer};

    // Vectors packed by Samba 4.22.11's NDR marshaller, from python3-samba,
    // with this script; each line it prints names the constant below.
    //
    //     import samba.ndr as n
    //     from samba.dcerpc import srvsvc
    //     def info1(name, typ, comment):
    //         i = srvsvc.NetShareInfo1(); i.name = name; i.type = typ
    //         i.comment = comment; return i
    //     def info501(name, typ, comment):
    //         i = srvsvc.NetShareInfo501(); i.name = name; i.type = typ
    //         i.comment = comment; i.csc_policy = 0; return i
    //     def info0(name):
    //         i = srvsvc.NetShareInfo0(); i.name = name; return i
    //     CTRS = {0: srvsvc.NetShareCtr0, 1: srvsvc.NetShareCtr1, 2: srvsvc.NetShareCtr2,
    //             501: srvsvc.NetShareCtr501, 1005: srvsvc.NetShareCtr1005}
    //     def ctr(level, arr):
    //         c = srvsvc.NetShareInfoCtr(); c.level = level
    //         if level in CTRS:
    //             x = CTRS[level](); x.count = len(arr); x.array = arr or None; c.ctr = x
    //         return c
    //     def enum_in(unc, c, max_buffer, resume):
    //         f = srvsvc.NetShareEnumAll(); f.in_server_unc = unc; f.in_info_ctr = c
    //         f.in_max_buffer = max_buffer; f.in_resume_handle = resume
    //         return n.ndr_pack_in(f).hex()
    //     def enum_out(c, total, resume, result):
    //         f = srvsvc.NetShareEnumAll(); f.out_info_ctr = c; f.out_totalentries = total
    //         f.out_resume_handle = resume; f.result = result
    //         return n.ndr_pack_out(f).hex()
    //     def get_in(unc, name, level):
    //         g = srvsvc.NetShareGetInfo(); g.in_server_unc = unc; g.in_share_name = name
    //         g.in_level = level; return n.ndr_pack_in(g).hex()
    //     def get_out(level, info, result):
    //         g = srvsvc.NetShareGetInfo(); g.in_level = level; g.out_info = info
    //         g.result = result; return n.ndr_pack_out(g).hex()
    //     def srv_in(unc, level):
    //         s = srvsvc.NetSrvGetInfo(); s.in_server_unc = unc; s.in_level = level
    //         return n.ndr_pack_in(s).hex()
    //     def srv_out(level, info, result):
    //         s = srvsvc.NetSrvGetInfo(); s.in_level = level; s.out_info = info
    //         s.result = result; return n.ndr_pack_out(s).hex()
    //     i100 = srvsvc.NetSrvInfo100(); i100.platform_id = 500; i100.server_name = "SRV"
    //     i101 = srvsvc.NetSrvInfo101(); i101.platform_id = 500; i101.server_name = "SRV"
    //     i101.version_major = 10; i101.version_minor = 0
    //     i101.server_type = 0x9003; i101.comment = ""
    //     i1005 = srvsvc.NetShareInfo1005(); i1005.dfs_flags = 0
    //     ipc = ("IPC$", 0x80000003, "Remote IPC")
    //     two = [info1(*ipc), info1("public", 0, "")]
    //     V = [
    //      ("ENUM_IN_L1", enum_in("\\\\SRV", ctr(1, []), 0xFFFFFFFF, 0)),
    //      ("ENUM_IN_L0_NULL", enum_in(None, ctr(0, []), 0xFFFFFFFF, None)),
    //      ("ENUM_IN_L501", enum_in("SRV", ctr(501, []), 200, 2)),
    //      ("ENUM_IN_L1005", enum_in("\\\\SRV", ctr(1005, []), 0xFFFFFFFF, 0)),
    //      ("GET_INFO_IN_L1", get_in("\\\\SRV", "public", 1)),
    //      ("SERVER_GET_INFO_IN_101", srv_in("\\\\SRV", 101)),
    //      ("ENUM_OUT_L1", enum_out(ctr(1, two), 2, 0, 0)),
    //      ("ENUM_OUT_L1_NO_RESUME", enum_out(ctr(1, two), 2, None, 0)),
    //      ("ENUM_OUT_L0", enum_out(ctr(0, [info0("IPC$"), info0("public")]), 2, 0, 0)),
    //      ("ENUM_OUT_L501",
    //       enum_out(ctr(501, [info501(*ipc), info501("docs", 0, "Docs")]), 2, 0, 0)),
    //      ("ENUM_OUT_L1_UTF16",
    //       enum_out(ctr(1, [info1("fotos", 0, "Fotos de \u00d1and\u00fa \U0001F9A4")]), 1, 0, 0)),
    //      ("ENUM_OUT_L1_MORE", enum_out(ctr(1, [info1("docs", 0, "Docs")]), 2, 2, 234)),
    //      ("ENUM_OUT_L1_EMPTY", enum_out(ctr(1, []), 0, 0, 0)),
    //      ("ENUM_OUT_L2_DENIED", enum_out(ctr(2, []), 0, 0, 5)),
    //      ("ENUM_OUT_L1005_INVALID", enum_out(ctr(1005, []), 0, 0, 124)),
    //      ("ENUM_OUT_L9", enum_out(ctr(9, []), 0, 0, 124)),
    //      ("GET_INFO_OUT_L1", get_out(1, info1("public", 0, "Files"), 0)),
    //      ("GET_INFO_OUT_L0", get_out(0, info0("public"), 0)),
    //      ("GET_INFO_OUT_L501", get_out(501, info501(*ipc), 0)),
    //      ("GET_INFO_OUT_L1005", get_out(1005, i1005, 0)),
    //      ("GET_INFO_OUT_NOT_FOUND", get_out(1, None, 2310)),
    //      ("GET_INFO_OUT_L2_DENIED", get_out(2, None, 5)),
    //      ("GET_INFO_OUT_L7", get_out(7, None, 124)),
    //      ("SERVER_GET_INFO_OUT_101", srv_out(101, i101, 0)),
    //      ("SERVER_GET_INFO_OUT_100", srv_out(100, i100, 0)),
    //      ("SERVER_GET_INFO_OUT_102_DENIED", srv_out(102, None, 5)),
    //     ]
    //     for name, value in V:
    //         print(name, value)

    /// server_unc "\\SRV", level 1, an empty container, max_buffer 0xFFFFFFFF, resume 0.
    const ENUM_IN_L1: &str = "000002000600000000000000060000005c005c0053005200560000000100000001000000040002000000000000000000ffffffff0800020000000000";
    /// no server_unc, level 0, max_buffer 0xFFFFFFFF, no resume handle.
    const ENUM_IN_L0_NULL: &str =
        "000000000000000000000000000002000000000000000000ffffffff00000000";
    /// server_unc "SRV", level 501, max_buffer 200, resume 2.
    const ENUM_IN_L501: &str = "000002000400000000000000040000005300520056000000f5010000f5010000040002000000000000000000c80000000800020002000000";
    /// level 1005, which Samba's IDL gives a container.
    const ENUM_IN_L1005: &str = "000002000600000000000000060000005c005c005300520056000000ed030000ed030000040002000000000000000000ffffffff0800020000000000";
    /// server_unc "\\SRV", share "public", level 1.
    const GET_INFO_IN_L1: &str = "000002000600000000000000060000005c005c0053005200560000000700000000000000070000007000750062006c00690063000000000001000000";
    /// server_unc "\\SRV", level 101.
    const SERVER_GET_INFO_IN_101: &str =
        "000002000600000000000000060000005c005c00530052005600000065000000";
    /// IPC$ 0x80000003 "Remote IPC" and public 0 ""; total 2, resume 0.
    const ENUM_OUT_L1: &str = "01000000010000000000020002000000040002000200000008000200030000800c0002001000020000000000140002000500000000000000050000004900500043002400000000000b000000000000000b000000520065006d006f00740065002000490050004300000000000700000000000000070000007000750062006c0069006300000000000100000000000000010000000000000002000000180002000000000000000000";
    /// the same with no resume handle.
    const ENUM_OUT_L1_NO_RESUME: &str = "01000000010000000000020002000000040002000200000008000200030000800c0002001000020000000000140002000500000000000000050000004900500043002400000000000b000000000000000b000000520065006d006f00740065002000490050004300000000000700000000000000070000007000750062006c00690063000000000001000000000000000100000000000000020000000000000000000000";
    /// level 0: IPC$ and public.
    const ENUM_OUT_L0: &str = "000000000000000000000200020000000400020002000000080002000c0002000500000000000000050000004900500043002400000000000700000000000000070000007000750062006c00690063000000000002000000100002000000000000000000";
    /// level 501: IPC$ and docs "Docs", flags 0.
    const ENUM_OUT_L501: &str = "f5010000f50100000000020002000000040002000200000008000200030000800c00020000000000100002000000000014000200000000000500000000000000050000004900500043002400000000000b000000000000000b000000520065006d006f007400650020004900500043000000000005000000000000000500000064006f00630073000000000005000000000000000500000044006f00630073000000000002000000180002000000000000000000";
    /// a remark with non-ASCII characters and a surrogate pair.
    const ENUM_OUT_L1_UTF16: &str = "01000000010000000000020001000000040002000100000008000200000000000c00020006000000000000000600000066006f0074006f007300000012000000000000001200000046006f0074006f0073002000640065002000d10061006e006400fa0020003ed8a4dd000001000000100002000000000000000000";
    /// one entry of two, resume 2, ERROR_MORE_DATA.
    const ENUM_OUT_L1_MORE: &str = "01000000010000000000020001000000040002000100000008000200000000000c00020005000000000000000500000064006f00630073000000000005000000000000000500000044006f006300730000000000020000001000020002000000ea000000";
    /// no entries, total 0.
    const ENUM_OUT_L1_EMPTY: &str =
        "010000000100000000000200000000000000000000000000040002000000000000000000";
    /// level 2, the empty container, ERROR_ACCESS_DENIED.
    const ENUM_OUT_L2_DENIED: &str =
        "020000000200000000000200000000000000000000000000040002000000000005000000";
    /// level 1005, the empty container, ERROR_INVALID_LEVEL.
    const ENUM_OUT_L1005_INVALID: &str =
        "ed030000ed0300000000020000000000000000000000000004000200000000007c000000";
    /// level 9, no arm, ERROR_INVALID_LEVEL.
    const ENUM_OUT_L9: &str = "09000000090000000000000000000200000000007c000000";
    /// public, type 0, remark "Files".
    const GET_INFO_OUT_L1: &str = "01000000000002000400020000000000080002000700000000000000070000007000750062006c006900630000000000060000000000000006000000460069006c0065007300000000000000";
    /// level 0: public.
    const GET_INFO_OUT_L0: &str =
        "0000000000000200040002000700000000000000070000007000750062006c00690063000000000000000000";
    /// level 501: IPC$.
    const GET_INFO_OUT_L501: &str = "f501000000000200040002000300008008000200000000000500000000000000050000004900500043002400000000000b000000000000000b000000520065006d006f007400650020004900500043000000000000000000";
    /// level 1005: flags 0.
    const GET_INFO_OUT_L1005: &str = "ed030000000002000000000000000000";
    /// level 1, NULL arm, NERR_NetNameNotFound.
    const GET_INFO_OUT_NOT_FOUND: &str = "010000000000000006090000";
    /// level 2, NULL arm, ERROR_ACCESS_DENIED.
    const GET_INFO_OUT_L2_DENIED: &str = "020000000000000005000000";
    /// level 7, no arm, ERROR_INVALID_LEVEL.
    const GET_INFO_OUT_L7: &str = "070000007c000000";
    /// platform 500, "SRV", 10.0, type 0x9003, comment "".
    const SERVER_GET_INFO_OUT_101: &str = "6500000000000200f4010000040002000a00000000000000039000000800020004000000000000000400000053005200560000000100000000000000010000000000000000000000";
    /// platform 500, "SRV".
    const SERVER_GET_INFO_OUT_100: &str =
        "6400000000000200f401000004000200040000000000000004000000530052005600000000000000";
    /// level 102, NULL arm, ERROR_ACCESS_DENIED.
    const SERVER_GET_INFO_OUT_102_DENIED: &str = "660000000000000005000000";

    fn share(name: &str, kind: u32, remark: &str) -> ListedShare {
        ListedShare {
            name: name.to_string(),
            kind,
            remark: remark.to_string(),
        }
    }

    fn view(shares: Vec<ListedShare>) -> ShareView {
        ShareView {
            server_name: "SRV".to_string(),
            shares,
        }
    }

    fn ipc() -> ListedShare {
        share("IPC$", STYPE_IPC_SPECIAL, "Remote IPC")
    }

    fn ok(opnum: u16, stub: &[u8], view: &ShareView) -> Vec<u8> {
        call(opnum, stub, view).expect("an answer")
    }

    fn enum_request(level: u32, preferred_max: u32, resume: Option<u32>) -> Vec<u8> {
        let mut w = NdrWriter::new();
        w.pointer(true);
        w.string("\\\\SRV");
        w.u32(level);
        w.u32(level);
        if ENUM_ARMS.contains(&level) {
            w.pointer(true);
            w.u32(0);
            w.pointer(false);
        }
        w.u32(preferred_max);
        w.pointer(resume.is_some());
        if let Some(resume) = resume {
            w.u32(resume);
        }
        w.finish()
    }

    fn get_info_request(name: &str, level: u32) -> Vec<u8> {
        let mut w = NdrWriter::new();
        w.pointer(false);
        w.string(name);
        w.u32(level);
        w.finish()
    }

    #[test]
    fn requests_decode() {
        assert_eq!(
            ShareEnum::decode(&unhex(ENUM_IN_L1)),
            Some(ShareEnum {
                level: 1,
                container: true,
                preferred_max: u32::MAX,
                resume: Some(0),
            })
        );
        assert_eq!(
            ShareEnum::decode(&unhex(ENUM_IN_L0_NULL)),
            Some(ShareEnum {
                level: 0,
                container: true,
                preferred_max: u32::MAX,
                resume: None,
            })
        );
        assert_eq!(
            ShareEnum::decode(&unhex(ENUM_IN_L501)),
            Some(ShareEnum {
                level: 501,
                container: true,
                preferred_max: 200,
                resume: Some(2),
            })
        );
        assert_eq!(
            ShareGetInfo::decode(&unhex(GET_INFO_IN_L1)),
            Some(ShareGetInfo {
                name: "public".to_string(),
                level: 1,
            })
        );
        assert_eq!(
            ServerGetInfo::decode(&unhex(SERVER_GET_INFO_IN_101)),
            Some(ServerGetInfo { level: 101 })
        );
    }

    #[test]
    fn share_enum_answers_match_samba() {
        let two = view(vec![ipc(), share("public", 0, "")]);
        assert_eq!(ok(15, &unhex(ENUM_IN_L1), &two), unhex(ENUM_OUT_L1));
        let no_resume = enum_request(1, u32::MAX, None);
        assert_eq!(ok(15, &no_resume, &two), unhex(ENUM_OUT_L1_NO_RESUME));
        let level_0 = enum_request(0, u32::MAX, Some(0));
        assert_eq!(ok(15, &level_0, &two), unhex(ENUM_OUT_L0));

        let docs = view(vec![ipc(), share("docs", 0, "Docs")]);
        let level_501 = enum_request(501, u32::MAX, Some(0));
        assert_eq!(ok(15, &level_501, &docs), unhex(ENUM_OUT_L501));

        let utf16 = view(vec![share(
            "fotos",
            0,
            "Fotos de \u{d1}and\u{fa} \u{1F9A4}",
        )]);
        assert_eq!(
            ok(15, &enum_request(1, u32::MAX, Some(0)), &utf16),
            unhex(ENUM_OUT_L1_UTF16)
        );
    }

    #[test]
    fn share_enum_refuses_levels_with_the_container_it_was_sent() {
        let two = view(vec![ipc(), share("public", 0, "")]);
        assert_eq!(
            ok(15, &enum_request(2, u32::MAX, Some(0)), &two),
            unhex(ENUM_OUT_L2_DENIED)
        );
        // Levels 502 and 503 have a container arm in MS-SRVS 2.2.3.5 and
        // are refused as level 2 is; Samba's IDL has no 503 arm, so these
        // expectations follow MS-SRVS 3.1.4.8 rather than Samba.
        for level in [502u32, 503] {
            let mut expected = unhex(ENUM_OUT_L2_DENIED);
            expected[..8].copy_from_slice(&[level.to_le_bytes(), level.to_le_bytes()].concat());
            assert_eq!(
                ok(15, &enum_request(level, u32::MAX, Some(0)), &two),
                expected
            );
        }
        assert_eq!(
            ok(15, &enum_request(9, u32::MAX, Some(0)), &two),
            unhex(ENUM_OUT_L9)
        );
    }

    #[test]
    fn samba_only_levels_get_their_container_back() {
        let two = view(vec![ipc(), share("public", 0, "")]);
        let request = unhex(ENUM_IN_L1005);
        assert_eq!(
            ShareEnum::decode(&request),
            Some(ShareEnum {
                level: 1005,
                container: true,
                preferred_max: u32::MAX,
                resume: Some(0),
            })
        );
        assert_eq!(ok(15, &request, &two), unhex(ENUM_OUT_L1005_INVALID));
    }

    #[test]
    fn share_enum_pages_by_ndr_size() {
        // At level 1, "s0" with an empty remark takes 12 + 20 + 16 = 48
        // bytes, and IPC$ 12 + 24 + 36 = 72.
        let shares = view(vec![
            share("s0", 0, ""),
            share("s1", 0, ""),
            share("s2", 0, ""),
            ipc(),
        ]);
        let page = |preferred: u32, resume: Option<u32>| {
            let answer = ok(15, &enum_request(1, preferred, resume), &shares);
            let tail = &answer[answer.len() - 16..];
            let word = |i: usize| u32::from_le_bytes(tail[4 * i..4 * i + 4].try_into().unwrap());
            let count = u32::from_le_bytes(answer[12..16].try_into().unwrap());
            // count, TotalEntries, resume handle, status.
            match resume {
                Some(_) => (count, word(0), word(2), word(3)),
                None => (count, word(1), 0, word(3)),
            }
        };
        assert_eq!(page(u32::MAX, Some(0)), (4, 4, 0, NERR_SUCCESS));
        assert_eq!(page(96, Some(0)), (2, 4, 2, ERROR_MORE_DATA));
        assert_eq!(page(95, Some(0)), (1, 4, 1, ERROR_MORE_DATA));
        assert_eq!(page(216, Some(0)), (4, 4, 0, NERR_SUCCESS));
        assert_eq!(page(215, Some(0)), (3, 4, 3, ERROR_MORE_DATA));
        // At least one entry, so a client always moves on.
        assert_eq!(page(0, Some(0)), (1, 4, 1, ERROR_MORE_DATA));
        assert_eq!(page(96, Some(2)), (1, 2, 3, ERROR_MORE_DATA));
        assert_eq!(page(1000, Some(3)), (1, 1, 0, NERR_SUCCESS));
        // A NULL resume handle starts at the beginning and gets none back.
        assert_eq!(page(96, None), (2, 4, 0, ERROR_MORE_DATA));
        // Past the end: success and no entries.
        for resume in [4, 5, u32::MAX] {
            let answer = ok(15, &enum_request(1, u32::MAX, Some(resume)), &shares);
            assert_eq!(answer, unhex(ENUM_OUT_L1_EMPTY), "{resume}");
        }
    }

    #[test]
    fn a_page_matches_samba() {
        let shares = view(vec![
            share("s0", 0, ""),
            share("docs", 0, "Docs"),
            share("more", 0, ""),
        ]);
        let answer = ok(15, &enum_request(1, 1, Some(1)), &shares);
        assert_eq!(answer, unhex(ENUM_OUT_L1_MORE));
    }

    #[test]
    fn share_get_info_answers_match_samba() {
        let shares = view(vec![share("public", 0, "Files"), ipc()]);
        let get = |name: &str, level: u32| ok(16, &get_info_request(name, level), &shares);
        assert_eq!(
            ok(16, &unhex(GET_INFO_IN_L1), &shares),
            unhex(GET_INFO_OUT_L1)
        );
        assert_eq!(get("PUBLIC", 1), unhex(GET_INFO_OUT_L1));
        assert_eq!(get("public", 0), unhex(GET_INFO_OUT_L0));
        assert_eq!(get("ipc$", 501), unhex(GET_INFO_OUT_L501));
        assert_eq!(get("public", 1005), unhex(GET_INFO_OUT_L1005));
        assert_eq!(get("nope", 1), unhex(GET_INFO_OUT_NOT_FOUND));
        assert_eq!(get("public", 2), unhex(GET_INFO_OUT_L2_DENIED));
        // MS-SRVS 2.2.3.6 gives levels 502 and 503 an arm, and 3.1.4.10 lists
        // both as valid; Samba's IDL has no 503 arm, so these expectations
        // follow MS-SRVS rather than Samba.
        for level in [502u32, 503] {
            let mut expected = unhex(GET_INFO_OUT_L2_DENIED);
            expected[..4].copy_from_slice(&level.to_le_bytes());
            assert_eq!(get("public", level), expected, "{level}");
        }
        assert_eq!(get("public", 7), unhex(GET_INFO_OUT_L7));
        // Levels with an arm but no answer, and an empty name.
        assert_eq!(
            get("public", 1004),
            [0xec, 3, 0, 0, 0, 0, 0, 0, 124, 0, 0, 0]
        );
        assert_eq!(get("", 1), [1, 0, 0, 0, 0, 0, 0, 0, 87, 0, 0, 0]);
    }

    #[test]
    fn server_get_info_answers_match_samba() {
        let srv = view(vec![ipc()]);
        let get = |level: u32| {
            let mut w = NdrWriter::new();
            w.pointer(false);
            w.u32(level);
            ok(21, &w.finish(), &srv)
        };
        assert_eq!(
            ok(21, &unhex(SERVER_GET_INFO_IN_101), &srv),
            unhex(SERVER_GET_INFO_OUT_101)
        );
        assert_eq!(get(100), unhex(SERVER_GET_INFO_OUT_100));
        // Levels 502 and 503 are refused as level 102 is (MS-SRVS 2.2.3.7,
        // 3.1.4.17).
        for level in [102u32, 502, 503] {
            let mut expected = unhex(SERVER_GET_INFO_OUT_102_DENIED);
            expected[..4].copy_from_slice(&level.to_le_bytes());
            assert_eq!(get(level), expected, "{level}");
        }
        assert_eq!(get(1005), [0xed, 3, 0, 0, 0, 0, 0, 0, 124, 0, 0, 0]);
        assert_eq!(get(7), [7, 0, 0, 0, 124, 0, 0, 0]);
    }

    fn caller(user: Option<&str>, can_encrypt: bool) -> Caller {
        let identity = match user {
            Some(name) => Identity::User {
                user: name.to_string(),
                domain: String::new(),
            },
            None => Identity::Anonymous,
        };
        Caller {
            identity,
            can_encrypt,
        }
    }

    fn names(shares: &[ListedShare]) -> Vec<&str> {
        shares.iter().map(|s| s.name.as_str()).collect()
    }

    #[tokio::test]
    async fn the_list_holds_what_the_caller_may_connect_to_in_insertion_order() {
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .user("alice", "password")
            .user("bob", "password")
            .share(Share::new("zeta", MemFsBackend::new()).public())
            .share(Share::new("home", MemFsBackend::new()).user("alice", Access::Read))
            .share(
                Share::new("hidden", MemFsBackend::new())
                    .public()
                    .listed(false),
            )
            .share(
                Share::new("alpha", MemFsBackend::new())
                    .public()
                    .remark("A"),
            )
            .build()
            .expect("build");
        let state = server.state();
        let list = async |who: &Caller| listed_shares(&state, who).await;
        let anonymous = caller(None, false);
        let shares = list(&anonymous).await;
        assert_eq!(names(&shares), ["zeta", "alpha", "IPC$"]);
        assert_eq!(shares[1], share("alpha", STYPE_DISKTREE, "A"));
        assert_eq!(shares[2], ipc());
        let alice = caller(Some("alice"), false);
        assert_eq!(
            names(&list(&alice).await),
            ["zeta", "home", "alpha", "IPC$"]
        );
        let bob = caller(Some("bob"), false);
        assert_eq!(names(&list(&bob).await), ["zeta", "alpha", "IPC$"]);

        let config = server.config_handle();
        config.remove_share("zeta").await.unwrap();
        for name in ["beta", "zeta"] {
            config
                .add_share(Share::new(name, MemFsBackend::new()).public())
                .await
                .unwrap();
        }
        assert_eq!(
            names(&list(&anonymous).await),
            ["alpha", "beta", "zeta", "IPC$"]
        );
    }

    #[tokio::test]
    async fn unlisted_shares_are_found_by_those_who_may_connect_to_them() {
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .user("alice", "password")
            .user("bob", "password")
            .share(
                Share::new("archive", MemFsBackend::new())
                    .user("alice", Access::Read)
                    .listed(false)
                    .remark("Old"),
            )
            .build()
            .expect("build");
        let state = server.state();
        let alice = caller(Some("alice"), false);
        assert_eq!(
            find_share(&state, &alice, "ARCHIVE").await,
            Some(share("archive", STYPE_DISKTREE, "Old"))
        );
        assert_eq!(
            find_share(&state, &caller(Some("bob"), false), "archive").await,
            None
        );
        assert_eq!(find_share(&state, &alice, "nope").await, None);
        assert_eq!(
            find_share(&state, &caller(None, false), "ipc$").await,
            Some(ipc())
        );
        assert_eq!(names(&listed_shares(&state, &alice).await), ["IPC$"]);
    }

    #[tokio::test]
    async fn shares_whose_traffic_is_encrypted_need_a_session_that_can_encrypt() {
        let build = |global: bool, reject: bool| {
            SmbServer::builder()
                .listen("127.0.0.1:0".parse().unwrap())
                .user("alice", "password")
                .share(Share::new("open", MemFsBackend::new()).public())
                .share(
                    Share::new("sealed", MemFsBackend::new())
                        .user("alice", Access::Read)
                        .encrypt_data(),
                )
                .encrypt_data(global)
                .reject_unencrypted_access(reject)
                .build()
                .expect("build")
                .state()
        };
        let plain = caller(Some("alice"), false);
        let sealed = caller(Some("alice"), true);

        let state = build(false, true);
        assert_eq!(
            names(&listed_shares(&state, &plain).await),
            ["open", "IPC$"]
        );
        assert_eq!(find_share(&state, &plain, "sealed").await, None);
        assert_eq!(
            names(&listed_shares(&state, &sealed).await),
            ["open", "sealed", "IPC$"]
        );
        assert!(find_share(&state, &sealed, "sealed").await.is_some());
        let anonymous = caller(None, false);
        assert_eq!(
            names(&listed_shares(&state, &anonymous).await),
            ["open", "IPC$"]
        );

        // Encryption for every session hides every share from one that
        // cannot encrypt.
        let state = build(true, true);
        assert_eq!(names(&listed_shares(&state, &plain).await), ["IPC$"]);
        assert_eq!(
            names(&listed_shares(&state, &sealed).await),
            ["open", "sealed", "IPC$"]
        );
        // Unless sessions that cannot encrypt are served unencrypted.
        let state = build(true, false);
        assert_eq!(
            names(&listed_shares(&state, &plain).await),
            ["open", "sealed", "IPC$"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn calls_read_only_the_shares_they_need() {
        let server = SmbServer::builder()
            .listen("127.0.0.1:0".parse().unwrap())
            .share(Share::new("a", MemFsBackend::new()).public())
            .share(Share::new("b", MemFsBackend::new()).public())
            .build()
            .expect("build");
        let state = server.state();
        let who = caller(None, false);
        let finishes = async |opnum: u16, stub: &[u8]| {
            let call = serve(&state, &who, opnum, stub);
            tokio::time::timeout(std::time::Duration::from_secs(60), call)
                .await
                .is_ok()
        };
        let server_info = {
            let mut w = NdrWriter::new();
            w.pointer(false);
            w.u32(101);
            w.finish()
        };
        let enum_all = enum_request(1, u32::MAX, None);

        // With one share's ACL held, a list waits for it, and the other
        // calls do not.
        let b = state.find_share("b").await.unwrap();
        let acl = b.acl.write().await;
        assert!(!finishes(15, &enum_all).await);
        assert!(finishes(16, &get_info_request("a", 1)).await);
        assert!(finishes(21, &server_info).await);
        assert!(finishes(99, &[]).await);
        drop(acl);

        // With the share table held, only the calls that read no share
        // finish.
        let table = state.shares.hold().await;
        assert!(!finishes(16, &get_info_request("a", 1)).await);
        assert!(finishes(16, &get_info_request("", 1)).await);
        assert!(finishes(21, &server_info).await);
        assert!(finishes(15, &[]).await);
        drop(table);
        assert!(finishes(15, &enum_all).await);
    }

    #[test]
    fn stubs_that_do_not_decode_fault_with_0x6f7() {
        let srv = view(vec![ipc()]);
        let bad = Fault {
            status: BAD_STUB_DATA,
            did_not_execute: false,
        };
        let enum_in = unhex(ENUM_IN_L1);
        let mut other_discriminant = enum_in.clone();
        other_discriminant[32] = 0;
        let mut with_buffer = enum_in.clone();
        with_buffer[44] = 4;
        let cases = [
            (15, enum_in[..enum_in.len() - 1].to_vec()),
            (15, other_discriminant),
            (15, with_buffer),
            (16, unhex(GET_INFO_IN_L1)[..20].to_vec()),
            (16, Vec::new()),
            (21, vec![0; 3]),
        ];
        for (opnum, stub) in cases {
            assert_eq!(call(opnum, &stub, &srv), Err(bad), "{opnum} {stub:02x?}");
        }
        assert_eq!(
            call(36, &[], &srv),
            Err(Fault {
                status: NCA_OP_RNG_ERROR,
                did_not_execute: true,
            })
        );
        // Bytes after the stub, such as a verification trailer, are left.
        let mut trailer = unhex(SERVER_GET_INFO_IN_101);
        trailer.extend_from_slice(&[0x8a, 0xe3, 0x13, 0x71, 0x02, 0xf4, 0x36, 0x71]);
        assert_eq!(ok(21, &trailer, &srv), unhex(SERVER_GET_INFO_OUT_101));
    }
}
