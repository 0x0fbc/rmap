use clap::{Arg, App};
use std::collections::HashSet;
use std::net::{IpAddr, TcpStream, SocketAddr};
use std::process::exit;
use std::str::FromStr;

fn main() {
    let argv = App::new("rmap")
        .version("0.1.0")
        .author("0x0fbc")
        .about("Toy Rust TCP connect scanner")
        .arg(Arg::with_name("targets")
            .takes_value(true)
            .required(true)
            .help("Target IPs comma separated, v4 or v6 \
            e.g. 172.16.1.3,DE:AD::BE:EF"))
        .arg(Arg::with_name("ports")
            .short("p")
            .long("ports")
            .takes_value(true)
            .required(false)
            .help("Ports to scan, comma separated. \
            Ranges may be specified with '-' e.g. 80,443,8080-8090 \
            If unspecified scans all ports. Ranges are inclusive."))
        .get_matches();

    // Parse comma separated ports and target lists into vecs of strings.
    // Targets is required so we can just unwrap it.
    let raw_targets: Vec<&str> = argv.value_of("targets").unwrap()
                                     .split(',').collect();

    let split_ports: Vec<&str>;
    match argv.value_of("ports") {
        Some(ports_in) => {
            split_ports = ports_in.split(',').collect();
        }
        // scan all ports by default
        None => {
            split_ports = vec!["1-65535"];
        }
    }

    // Determine the ports to be scanned
    let mut ports: HashSet<u16> = HashSet::new();
    for port_spec in split_ports {
        if port_spec.contains('-') {
            let range_spec: Vec<&str> = port_spec.split('-').collect();
            if range_spec.len() != 2 {
                // Check that the spec is properly formed
                println!("Improper port range specification: {}",
                         port_spec);
                exit(1);
            } else {
                // Extract a start and end from the range
                let start = range_spec.get(0).unwrap()
                                      .parse::<u16>().unwrap();
                let end = range_spec.get(1).unwrap()
                                      .parse::<u16>().unwrap();
                // Check that the range's values make sense
                if start > end {
                    println!("Improper port range specification: {}",
                             port_spec);
                    exit(2);
                }

                // Generate a range from the provided start & stop and insert
                // into the ports set.
                for port in start..=end {
                    ports.insert(port);
                }
            }
        } else {
            // assume it's a single port, parse it, and insert
            match port_spec.parse::<u16>() {
                Ok(p) => {ports.insert(p);},
                Err(_e) => () // Do Nothing
            }
        }
    }

    let mut targets: Vec<IpAddr> = Vec::new();
    for raw_target in raw_targets {
        match IpAddr::from_str(raw_target) {
            Ok(addr) => {
                targets.push(addr);
            },
            Err(_e) => {
                println!("Invalid target {}", raw_target);
                exit(1);
            }
        }
    }

    // Simplest possible scan
    for target in targets {
        let mut open: Vec<u16> = Vec::new();
        for port in &ports {
            // if TCP Stream doesn't error the port must be open
            match TcpStream::connect(SocketAddr::new(target, *port)) {
                Ok(_c) => open.push(*port),
                Err(_e) => ()
            }
        }
        for port in open {
            println!("{}: OPEN {}", target, port);
        }
    }
}
