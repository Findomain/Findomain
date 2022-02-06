// use {
//     rayon::prelude::*,
//     std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
// };

// pub fn return_open_ports(ports: &[u16], ip_address: Ipv4Addr, timeout: u64) -> Vec<i32> {
//     let lightweight_tasks_pool = rayon::ThreadPoolBuilder::new()
//         .num_threads(100)
//         .build()
//         .unwrap();
//     let mut open_ports: Vec<i32> = lightweight_tasks_pool
//         .install(|| {
//             ports.par_iter().map(|port| {
//                 if TcpStream::connect_timeout(
//                     &SocketAddr::new(IpAddr::from(ip_address), *port),
//                     std::time::Duration::from_millis(timeout),
//                 )
//                 .is_ok()
//                 {
//                     i32::from(*port)
//                 } else {
//                     0
//                 }
//             })
//         })
//         .collect();
//     open_ports.retain(|port| port != &0);
//     open_ports
// }
