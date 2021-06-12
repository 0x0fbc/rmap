use clap::{Arg, App};

fn main() {
    let argv = App::new("rmap")
        .version("0.1.0")
        .author("0x0fbc")
        .about("Toy Rust TCP connect scanner")
        .arg(Arg::with_name("targets")
            .takes_value(true)
            .help("Target IPs comma separated, v4 or v6 \
            e.g. 172.16.1.3,DE:AD::BE:EF"))
        .arg(Arg::with_name("ports")
            .short("p")
            .long("ports")
            .takes_value(true)
            .required(true)
            .help("Ports to scan, comma separated and ranges specified with - \
            e.g. 80,443,8080-8090 \
            If unspecified scans all ports. Ranges are inclusive."))
        .get_matches();

    // split target and port lists up
    let targets: Vec<&str> = argv.value_of("targets").unwrap()
                                     .split(",").collect();
    let ports: Vec<&str> = argv.value_of("ports").unwrap()
                                   .split(",").collect();
}
