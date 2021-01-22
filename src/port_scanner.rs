use {
    rayon::prelude::*,
    std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
};

pub fn return_open_ports(ports: &[u16], ip_address: Ipv4Addr, timeout: u64) -> Vec<i32> {
    let mut open_ports = Vec::new();
    open_ports.par_extend(ports.par_iter().map(|port| {
        if TcpStream::connect_timeout(
            &SocketAddr::new(IpAddr::from(ip_address), *port),
            std::time::Duration::from_millis(timeout),
        )
        .is_ok()
        {
            i32::from(*port)
        } else {
            0
        }
    }));
    open_ports.retain(|port| port != &0);
    open_ports
}
