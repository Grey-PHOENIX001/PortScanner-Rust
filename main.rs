use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use chrono::{Local, DateTime};
use tokio::time::{Duration, timeout};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let target_ip = "127.0.0.1"; // Replace with the IP address you want to scan
    let target_ip: IpAddr = target_ip.parse()?;
    let start_port = 1;
    let end_port = 65535;
    let timeout_duration = Duration::from_secs(2); // Adjust the timeout as needed

    // Write "Here is the scan result" to the 'open_ports_logs.txt' file when the scanning process starts.
    if let Err(err) = write_to_file("open_ports_logs.txt", "\n\nHere is the scan result").await {
        eprintln!("Error writing to file: {}", err);
    }

    let open_ports = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let start_time = Local::now();

    for port in start_port..=end_port {
        let socket_addr = SocketAddr::new(target_ip, port);
        let open_ports = open_ports.clone();

        tokio::spawn(async move {
            match scan_port(socket_addr, timeout_duration).await {
                Ok(_) => {
                    let now: DateTime<Local> = Local::now();
                    let result = format!(
                        "Port {} is open - Scanned at {}",
                        socket_addr.port(),
                        now.format("%Y-%m-%d %H:%M:%S")
                    );
                    println!("{}", result);

                    // Clone the result before pushing it into the vector.
                    let mut open_ports = open_ports.lock().await;
                    open_ports.push(result.clone());

                    // Write each result line to the 'open_ports_logs.txt' file.
                    if let Err(err) = write_to_file("open_ports_logs.txt", &result).await {
                        eprintln!("Error writing to file: {}", err);
                    }
                }
                Err(err) => {
                    println!("Port {} error: {}", socket_addr.port(), err);
                }
            }
        });
    }

    tokio::time::sleep(Duration::from_secs(5)).await; // Adjust the sleep duration as needed

    let open_ports = open_ports.lock().await;
    for port_result in &*open_ports {
        println!("{}", port_result);

        // Extract the open port number and write it to the 'open_ports.txt' file line by line.
        let port_number = extract_port_number(&port_result);
        if let Some(port) = port_number {
            if let Err(err) = write_to_file("open_ports.txt", &port.to_string()).await {
                eprintln!("Error writing to file: {}", err);
            }
        }
    }

    let end_time = Local::now();
    let duration = end_time.signed_duration_since(start_time);
    let time_taken = format!("Scanning completed in {} seconds", duration.num_seconds());
    println!("{}", time_taken);

    // Write the time taken for scanning to the 'open_ports_logs.txt' file.
    if let Err(err) = write_to_file("open_ports_logs.txt", &time_taken).await {
        eprintln!("Error writing time taken to file: {}", err);
    }

    Ok(())
}

async fn scan_port(socket_addr: SocketAddr, timeout_duration: Duration) -> Result<(), Box<dyn Error + Send + Sync>> {
    let tcp_stream = TcpStream::connect(&socket_addr);
    let result = timeout(timeout_duration, tcp_stream).await;

    match result {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) => Err(format!("Port error: {}", err).into()),
        Err(_) => Err("Connection timed out".into()),
    }
}

async fn write_to_file(file_name: &str, content: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_name)?;

    file.write_all(content.as_bytes())?;
    file.write_all(b"\n")?; // Write a newline after each result line

    Ok(())
}

fn extract_port_number(result: &str) -> Option<u16> {
    let parts: Vec<&str> = result.split_whitespace().collect();
    if parts.len() >= 2 {
        match parts[1].parse() {
            Ok(port) => Some(port),
            Err(_) => None,
        }
    } else {
        None
    }
}
