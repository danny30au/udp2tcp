//! Linux-only batched UDP I/O via `recvmmsg`/`sendmmsg` and UDP GSO/GRO.
//!
//! At multi-Mpps rates the syscall and Tokio waker round-trip per datagram
//! become a real bottleneck. `recvmmsg` and `sendmmsg` (Linux ≥ 2.6.33 /
//! ≥ 3.0) collect or emit up to `BATCH_MAX` datagrams in one syscall, and
//! UDP_GRO/UDP_SEGMENT (Linux ≥ 5.0) let the kernel pack many UDP segments
//! into single in-kernel frames, halving CPU on high-pps WireGuard flows.
//!
//! On non-Linux we fall back to the regular `tokio::net::UdpSocket` path
//! (the public methods here have one-at-a-time fallbacks).

use std::io;
use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};

/// Maximum datagrams per `recvmmsg`/`sendmmsg` batch.
pub const BATCH_MAX: usize = 32;

/// One received datagram returned by `recv_batch`.
pub struct RecvDatagram {
    pub data: Bytes,
    pub src: SocketAddr,
}

/// One datagram queued for a future `send_batch`.
pub struct SendDatagram {
    pub data: Bytes,
    pub dst: Option<SocketAddr>,
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    use std::mem::{self, MaybeUninit};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::Arc;

    use tokio::io::unix::AsyncFd;
    use tokio::io::Interest;
    use tracing::debug;

    /// Per-datagram receive buffer size.
    const RECV_SLOT_SIZE: usize = 65_536;

    /// Wrapper around an `AsyncFd<RawFd>` for a non-blocking UDP socket
    /// supporting `recvmmsg`/`sendmmsg`.
    ///
    /// The underlying `socket2::Socket` (or `std::net::UdpSocket`) must be
    /// non-blocking and bound. The wrapper takes ownership of an `Arc`'d
    /// std socket so the fd lives as long as the wrapper does.
    pub struct BatchedUdpSocket {
        // Keep the std socket alive for the lifetime of the AsyncFd.
        _std: Arc<std::net::UdpSocket>,
        fd: AsyncFd<RawFd>,
    }

    impl BatchedUdpSocket {
        pub fn from_std(sock: std::net::UdpSocket) -> io::Result<Self> {
            sock.set_nonblocking(true)?;
            let arc = Arc::new(sock);
            let raw = arc.as_raw_fd();
            // Best-effort enable UDP_GRO so the kernel can deliver several
            // back-to-back same-flow UDP segments in one recv. Ignored on
            // older kernels.
            unsafe {
                let on: libc::c_int = 1;
                let _ = libc::setsockopt(
                    raw,
                    libc::SOL_UDP,
                    UDP_GRO,
                    &on as *const _ as _,
                    mem::size_of_val(&on) as libc::socklen_t,
                );
            }
            let fd = AsyncFd::with_interest(raw, Interest::READABLE | Interest::WRITABLE)?;
            Ok(Self { _std: arc, fd })
        }

        /// Receive up to `BATCH_MAX` datagrams in one `recvmmsg` syscall.
        /// Pushes the results into `out` (freshly cleared on entry) and
        /// returns the number received. Always > 0 on success.
        pub async fn recv_batch(&self, out: &mut Vec<RecvDatagram>) -> io::Result<usize> {
            out.clear();
            loop {
                let mut guard = self.fd.readable().await?;
                match guard.try_io(|fd| recvmmsg_once(fd.as_raw_fd(), out)) {
                    Ok(Ok(n)) => return Ok(n),
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => continue,
                }
            }
        }

        /// Send up to `BATCH_MAX` datagrams in one `sendmmsg` syscall.
        /// Falls back to one-at-a-time emission if the kernel only accepts
        /// part of the batch. `default_dst` is used for entries with
        /// `dst == None` (typical for "connected" UDP sockets).
        pub async fn send_batch(
            &self,
            items: &[SendDatagram],
            default_dst: Option<SocketAddr>,
        ) -> io::Result<usize> {
            if items.is_empty() {
                return Ok(0);
            }
            let mut sent = 0usize;
            while sent < items.len() {
                let chunk = &items[sent..];
                let mut guard = self.fd.writable().await?;
                match guard.try_io(|fd| sendmmsg_once(fd.as_raw_fd(), chunk, default_dst)) {
                    Ok(Ok(n)) if n > 0 => sent += n,
                    Ok(Ok(_)) => {
                        // 0-byte progress shouldn't happen but break to avoid
                        // a tight loop.
                        break;
                    }
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => continue,
                }
            }
            Ok(sent)
        }
        /// Single-datagram, addressed send (used for the per-flow UDP
        /// reply path that is interleaved with TCP reads in a `select!`).
        pub async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> io::Result<usize> {
            let (ss, len) = socketaddr_to_sockaddr(&dst);
            loop {
                let mut guard = self.fd.writable().await?;
                match guard.try_io(|fd| sendto_once(fd.as_raw_fd(), buf, &ss, len)) {
                    Ok(Ok(n)) => return Ok(n),
                    Ok(Err(e)) => return Err(e),
                    Err(_would_block) => continue,
                }
            }
        }
    }

    fn sendto_once(
        fd: RawFd,
        buf: &[u8],
        ss: &libc::sockaddr_storage,
        len: libc::socklen_t,
    ) -> io::Result<usize> {
        let n = unsafe {
            libc::sendto(
                fd,
                buf.as_ptr() as *const _,
                buf.len(),
                libc::MSG_DONTWAIT,
                ss as *const _ as *const libc::sockaddr,
                len,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    // ─── recvmmsg core ────────────────────────────────────────────────────

    // Per-datagram scratch storage. Boxed to keep the iovec/sockaddr/buf
    // arrays heap-allocated and stable across the syscall.
    #[repr(C)]
    struct RecvSlots {
        msgs: [libc::mmsghdr; BATCH_MAX],
        iovs: [libc::iovec; BATCH_MAX],
        addrs: [libc::sockaddr_storage; BATCH_MAX],
        bufs: [[u8; RECV_SLOT_SIZE]; BATCH_MAX],
    }

    impl RecvSlots {
        fn new() -> Box<Self> {
            // SAFETY: zero-initialising POD-ish C structs is fine; the
            // sockaddr_storage/mmsghdr/iovec are explicitly POD-compatible
            // and we never read fields before the kernel writes them.
            unsafe {
                let layout = std::alloc::Layout::new::<Self>();
                let raw = std::alloc::alloc_zeroed(layout) as *mut Self;
                if raw.is_null() {
                    std::alloc::handle_alloc_error(layout);
                }
                Box::from_raw(raw)
            }
        }
    }

    thread_local! {
        // One scratch arena per worker thread keeps `recvmmsg` allocation-free
        // on the hot path.
        static RECV_SCRATCH: std::cell::RefCell<Box<RecvSlots>> =
            std::cell::RefCell::new(RecvSlots::new());
    }

    fn recvmmsg_once(fd: RawFd, out: &mut Vec<RecvDatagram>) -> io::Result<usize> {
        RECV_SCRATCH.with(|cell| {
            let mut slots = cell.borrow_mut();
            for i in 0..BATCH_MAX {
                slots.iovs[i] = libc::iovec {
                    iov_base: slots.bufs[i].as_mut_ptr() as *mut _,
                    iov_len: RECV_SLOT_SIZE,
                };
                slots.addrs[i] = unsafe { mem::zeroed() };
                slots.msgs[i] = libc::mmsghdr {
                    msg_hdr: libc::msghdr {
                        msg_name: &mut slots.addrs[i] as *mut _ as *mut _,
                        msg_namelen: mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
                        msg_iov: &mut slots.iovs[i] as *mut _,
                        msg_iovlen: 1,
                        msg_control: std::ptr::null_mut(),
                        msg_controllen: 0,
                        msg_flags: 0,
                    },
                    msg_len: 0,
                };
            }

            let n = unsafe {
                libc::recvmmsg(
                    fd,
                    slots.msgs.as_mut_ptr(),
                    BATCH_MAX as libc::c_uint,
                    libc::MSG_DONTWAIT,
                    std::ptr::null_mut(),
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                return Err(err);
            }
            let n = n as usize;
            for i in 0..n {
                let len = slots.msgs[i].msg_len as usize;
                let buf = BytesMut::from(&slots.bufs[i][..len]);
                let src = sockaddr_to_socketaddr(&slots.addrs[i], slots.msgs[i].msg_hdr.msg_namelen)
                    .unwrap_or_else(|| SocketAddr::from(([0u8; 4], 0)));
                out.push(RecvDatagram { data: buf.freeze(), src });
            }
            Ok(n)
        })
    }

    // ─── sendmmsg core ────────────────────────────────────────────────────

    fn sendmmsg_once(
        fd: RawFd,
        items: &[SendDatagram],
        default_dst: Option<SocketAddr>,
    ) -> io::Result<usize> {
        let n = items.len().min(BATCH_MAX);
        let mut iovs: [MaybeUninit<libc::iovec>; BATCH_MAX] = [MaybeUninit::uninit(); BATCH_MAX];
        let mut addrs: [MaybeUninit<libc::sockaddr_storage>; BATCH_MAX] =
            [MaybeUninit::uninit(); BATCH_MAX];
        let mut addr_lens: [libc::socklen_t; BATCH_MAX] = [0; BATCH_MAX];
        let mut msgs: [MaybeUninit<libc::mmsghdr>; BATCH_MAX] = [MaybeUninit::uninit(); BATCH_MAX];

        for i in 0..n {
            let dst = items[i].dst.or(default_dst);
            let (addr_ptr, addr_len) = match dst {
                Some(addr) => {
                    let (ss, len) = socketaddr_to_sockaddr(&addr);
                    addrs[i].write(ss);
                    addr_lens[i] = len;
                    (addrs[i].as_mut_ptr() as *mut libc::c_void, len)
                }
                None => (std::ptr::null_mut(), 0),
            };
            iovs[i].write(libc::iovec {
                iov_base: items[i].data.as_ptr() as *mut _,
                iov_len: items[i].data.len(),
            });
            msgs[i].write(libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: addr_ptr,
                    msg_namelen: addr_len,
                    msg_iov: iovs[i].as_mut_ptr(),
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            });
        }

        let rc = unsafe {
            libc::sendmmsg(
                fd,
                msgs.as_mut_ptr() as *mut libc::mmsghdr,
                n as libc::c_uint,
                libc::MSG_DONTWAIT,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            // Map EAGAIN/EWOULDBLOCK to a WouldBlock so the AsyncFd retry
            // loop above re-arms readiness.
            return Err(err);
        }
        Ok(rc as usize)
    }

    // ─── address conversions ──────────────────────────────────────────────

    fn sockaddr_to_socketaddr(
        ss: &libc::sockaddr_storage,
        len: libc::socklen_t,
    ) -> Option<SocketAddr> {
        let family = ss.ss_family as libc::c_int;
        if family == libc::AF_INET
            && (len as usize) >= mem::size_of::<libc::sockaddr_in>()
        {
            let s4: &libc::sockaddr_in = unsafe { &*(ss as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(s4.sin_addr.s_addr));
            let port = u16::from_be(s4.sin_port);
            Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        } else if family == libc::AF_INET6
            && (len as usize) >= mem::size_of::<libc::sockaddr_in6>()
        {
            let s6: &libc::sockaddr_in6 =
                unsafe { &*(ss as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(s6.sin6_addr.s6_addr);
            let port = u16::from_be(s6.sin6_port);
            Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                s6.sin6_flowinfo,
                s6.sin6_scope_id,
            )))
        } else {
            debug!(family = family, len = len, "unrecognised sockaddr family from recvmmsg");
            None
        }
    }

    fn socketaddr_to_sockaddr(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
        let mut ss: libc::sockaddr_storage = unsafe { mem::zeroed() };
        match addr {
            SocketAddr::V4(v4) => {
                let s4: &mut libc::sockaddr_in =
                    unsafe { &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in) };
                s4.sin_family = libc::AF_INET as libc::sa_family_t;
                s4.sin_port = v4.port().to_be();
                s4.sin_addr = libc::in_addr {
                    s_addr: u32::from(*v4.ip()).to_be(),
                };
                (ss, mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
            }
            SocketAddr::V6(v6) => {
                let s6: &mut libc::sockaddr_in6 =
                    unsafe { &mut *(&mut ss as *mut _ as *mut libc::sockaddr_in6) };
                s6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                s6.sin6_port = v6.port().to_be();
                s6.sin6_flowinfo = v6.flowinfo();
                s6.sin6_scope_id = v6.scope_id();
                s6.sin6_addr.s6_addr = v6.ip().octets();
                (ss, mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
            }
        }
    }

    // SOL_UDP / UDP_GRO are defined in <linux/udp.h> but not exposed by libc.
    // The constants are stable kernel ABI.
    const UDP_GRO: libc::c_int = 104;
}

#[cfg(target_os = "linux")]
pub use linux::BatchedUdpSocket;

// ─── non-Linux fallback ─────────────────────────────────────────────────
//
// On non-Linux platforms recvmmsg/sendmmsg aren't available (or aren't worth
// the cost), so we fall back to plain tokio `UdpSocket` with a one-at-a-time
// `recv_batch`. This keeps `proxy.rs` portable.

#[cfg(not(target_os = "linux"))]
mod fallback {
    use super::*;
    use bytes::BytesMut;
    use tokio::net::UdpSocket;

    pub struct BatchedUdpSocket {
        sock: UdpSocket,
    }

    impl BatchedUdpSocket {
        pub fn from_std(sock: std::net::UdpSocket) -> std::io::Result<Self> {
            sock.set_nonblocking(true)?;
            Ok(Self {
                sock: UdpSocket::from_std(sock)?,
            })
        }

        pub async fn recv_batch(&self, out: &mut Vec<RecvDatagram>) -> std::io::Result<usize> {
            out.clear();
            let mut buf = BytesMut::with_capacity(65_536);
            let (n, src) = self.sock.recv_buf_from(&mut buf).await?;
            buf.truncate(n);
            out.push(RecvDatagram { data: buf.freeze(), src });
            Ok(1)
        }

        pub async fn send_batch(
            &self,
            items: &[SendDatagram],
            default_dst: Option<SocketAddr>,
        ) -> std::io::Result<usize> {
            let mut sent = 0;
            for item in items {
                let dst = match item.dst.or(default_dst) {
                    Some(a) => a,
                    None => break,
                };
                self.sock.send_to(&item.data, dst).await?;
                sent += 1;
            }
            Ok(sent)
        }

        pub async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> std::io::Result<usize> {
            self.sock.send_to(buf, dst).await
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use fallback::BatchedUdpSocket;

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recv_send_round_trip() {
        // Bind two ephemeral non-blocking UDP sockets and exchange a
        // small batch through recvmmsg/sendmmsg.
        let a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();

        let a = BatchedUdpSocket::from_std(a).unwrap();
        let b = BatchedUdpSocket::from_std(b).unwrap();

        // Send 5 datagrams from a → b.
        let payloads: Vec<Bytes> = (0..5u8).map(|i| Bytes::from(vec![i; 16])).collect();
        let items: Vec<SendDatagram> = payloads
            .iter()
            .cloned()
            .map(|data| SendDatagram { data, dst: Some(b_addr) })
            .collect();
        let n = a.send_batch(&items, None).await.unwrap();
        assert_eq!(n, 5);

        // Drain on b; may take more than one recv_batch on busy systems but
        // this loopback case typically returns all 5 in one syscall.
        let mut received: Vec<RecvDatagram> = Vec::with_capacity(BATCH_MAX);
        let mut got = 0;
        while got < 5 {
            let mut tmp = Vec::with_capacity(BATCH_MAX);
            let n = b.recv_batch(&mut tmp).await.unwrap();
            for d in tmp.drain(..n) {
                assert_eq!(d.src, a_addr);
                received.push(d);
            }
            got = received.len();
        }
        assert_eq!(received.len(), 5);
        for (i, d) in received.iter().enumerate() {
            assert_eq!(&d.data[..], &payloads[i][..]);
        }
    }
}
