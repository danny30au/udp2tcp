//! WireGuard-over-TCP length-prefix codec.
//!
//! The wire format is identical to the TCP transport used by wg-tcp-tunnel
//! and similar tools: a 2-byte big-endian unsigned integer length prefix
//! followed by the raw WireGuard UDP packet payload.
//!
//!  ┌──────────────────────┬──────────────────────────────────┐
//!  │  Length (2 bytes BE) │  WireGuard packet (1–65535 bytes)│
//!  └──────────────────────┴──────────────────────────────────┘
//!
//! This is the same framing used by:
//!   - wireguard-tcp (boringtun wrapper)
//!   - wstunnel (websocket/tcp WireGuard transport)
//!   - wg-tcp-tunnel

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::error::ProxyError;

/// Maximum WireGuard datagram size.
/// The real limit is ~1500 bytes for handshake/keepalive, up to ~1500 for data.
/// We allow up to 65535 to be safe.
pub const MAX_DATAGRAM_SIZE: usize = 65535;

/// 2-byte big-endian length-prefix codec for WireGuard UDP datagrams over TCP.
#[derive(Default, Debug, Clone, Copy)]
pub struct WireGuardTcpCodec;

impl Decoder for WireGuardTcpCodec {
    type Item = BytesMut;
    type Error = ProxyError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Need at least 2 bytes for the length prefix.
        if src.len() < 2 {
            src.reserve(2);
            return Ok(None);
        }

        // Peek the length without consuming.
        let len = u16::from_be_bytes([src[0], src[1]]) as usize;

        if len == 0 || len > MAX_DATAGRAM_SIZE {
            return Err(ProxyError::InvalidFrame(format!(
                "invalid frame length: {len}"
            )));
        }

        // Not enough data yet for the full frame.
        let total = 2 + len;
        if src.len() < total {
            src.reserve(total - src.len());
            return Ok(None);
        }

        // Consume the 2-byte prefix.
        src.advance(2);

        // Split off exactly `len` bytes for this frame.
        let data = src.split_to(len);
        Ok(Some(data))
    }
}

impl Encoder<bytes::Bytes> for WireGuardTcpCodec {
    type Error = ProxyError;

    fn encode(&mut self, item: bytes::Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let len = item.len();
        if len == 0 || len > MAX_DATAGRAM_SIZE {
            return Err(ProxyError::InvalidFrame(format!(
                "cannot encode frame of length {len}"
            )));
        }
        dst.reserve(2 + len);
        dst.put_u16(len as u16);
        dst.put(item);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn round_trip() {
        let payload = Bytes::from_static(b"hello wireguard");
        let mut codec = WireGuardTcpCodec;
        let mut buf = BytesMut::new();

        codec.encode(payload.clone(), &mut buf).unwrap();
        assert_eq!(buf.len(), 2 + payload.len());

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.as_ref(), payload.as_ref());
    }

    #[test]
    fn partial_frame_returns_none() {
        let mut codec = WireGuardTcpCodec;
        let mut buf = BytesMut::from(&[0u8, 10u8, 1u8, 2u8][..]);
        // Only 2 bytes of a 10-byte payload: should return None.
        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_none());
    }
}
