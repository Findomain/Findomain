use {
    futures::stream::{self, StreamExt},
    std::collections::{HashMap, HashSet},
    tokio::{net::TcpStream, time::timeout},
};

pub async fn return_open_ports_from_ips(
    ports: Vec<u16>,
    ips: HashSet<String>,
    parallel_ip_ports_scan: usize,
    tcp_connect_timeout: u64,
    tcp_connect_threads: usize,
) -> HashMap<String, Vec<i32>> {
    stream::iter(ips)
        .map(|ip| {
            let ports = ports.clone();
            async move {
                let ports_data =
                    return_open_ports(ports, &ip, tcp_connect_timeout, tcp_connect_threads).await;

                (ip, ports_data)
            }
        })
        .buffer_unordered(parallel_ip_ports_scan)
        .collect::<HashMap<String, Vec<i32>>>()
        .await
}

pub async fn return_open_ports(
    ports: Vec<u16>,
    ip_address: &str,
    timeout_duration: u64,
    threads: usize,
) -> Vec<i32> {
    let mut open_ports: Vec<i32> = stream::iter(ports)
        .map(|port| async move {
            if timeout(
                std::time::Duration::from_millis(timeout_duration),
                TcpStream::connect(format!("{ip_address}:{port}")),
            )
            .await
            .is_ok()
            {
                i32::from(port)
            } else {
                0
            }
        })
        .buffer_unordered(threads)
        .collect()
        .await;

    open_ports.retain(|port| port != &0);
    open_ports
}
