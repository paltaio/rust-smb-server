//! Backend that stores file contents and names encrypted under a caller key.

#[cfg_attr(not(test), expect(dead_code, reason = "only tests use it so far"))]
mod block;
#[cfg_attr(not(test), expect(dead_code, reason = "only tests use it so far"))]
mod format;
#[cfg_attr(not(test), expect(dead_code, reason = "only tests use it so far"))]
mod header;
#[cfg_attr(not(test), expect(dead_code, reason = "only tests use it so far"))]
mod keys;
#[cfg_attr(not(test), expect(dead_code, reason = "only tests use it so far"))]
mod marker;
#[cfg_attr(not(test), expect(dead_code, reason = "only tests use it so far"))]
mod random;
#[cfg_attr(not(test), expect(dead_code, reason = "only tests use it so far"))]
mod size;
#[cfg(test)]
mod testing;
#[cfg(test)]
mod wycheproof_gcm;
