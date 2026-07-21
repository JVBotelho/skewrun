use std::io;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use socket2::{Domain, Protocol, SockRef, Socket, Type};

const WINDOWS_TTL: u32 = 128;

pub fn connect_tcp_with_ttl(addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    if addr.is_ipv4() {
        socket.set_ttl(WINDOWS_TTL)?;
    } else {
        socket.set_unicast_hops_v6(WINDOWS_TTL)?;
    }
    socket.set_nodelay(false)?;

    socket.connect_timeout(&addr.into(), timeout)?;

    Ok(TcpStream::from(socket))
}

pub fn set_windows_ttl_udp(socket: &UdpSocket) -> io::Result<()> {
    let is_ipv4 = socket.local_addr()?.is_ipv4();
    let sock_ref = SockRef::from(socket);
    if is_ipv4 {
        sock_ref.set_ttl(WINDOWS_TTL)?;
    } else {
        sock_ref.set_unicast_hops_v6(WINDOWS_TTL)?;
    }
    Ok(())
}
