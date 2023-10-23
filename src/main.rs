use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::sync::mpsc::{Sender, channel};
use tokio::net::TcpStream;
use tokio::task;
use bpaf::Bpaf;

const MAX_PORT: u16 = 65535;
const IPFALLBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 0);

#[derive(Debug, Clone, Bpaf)]
#[bpaf(options)]

pub struct Arguments {
    #[bpaf(long, short, fallback(IPFALLBACK))]
    /// The address that you want to sniff. Must be a valid IPv4 address. Falls back to 127.0.0.0.
    pub address: Ipv4Addr,

    #[bpaf(long("start"), short('s'), fallback(1u16), guard(start_port_guard, "Must be greater than 0."))]
    /// The start port for the sniffer. Must be greater than 0.
    pub start_port: u16,

    #[bpaf(long("end"), short('e'), fallback(MAX_PORT), guard(end_port_guard, "Must be less than or equal to 65535."))]
    /// The end port for the sniffer. Must be less than or equal to than 65535.
    pub end_port: u16,
}

fn start_port_guard(input: &u16) -> bool {
    return *input > 0;
}

fn end_port_guard(input: &u16) -> bool {
    return *input <= MAX_PORT;
}

async fn scan(tx: Sender<u16>, port: u16, addr: Ipv4Addr) {
    match TcpStream::connect(format!("{addr}:{port}")).await {
        Ok(_) => {
            print!(".");
            io::stdout().flush().unwrap();
            tx.send(port).unwrap();
        }
        Err(_) => {}
    };
}

#[tokio::main]
async fn main() {
    let opts: Arguments = arguments().run();

    let (tx, rx) = channel();
    for i in opts.start_port..opts.end_port {
        let tx = tx.clone();
        task::spawn(async move {
            scan(tx, i, opts.address).await;
        });
    }

    let mut out = vec![];
    drop(tx);
    for p in rx {
        out.push(p);
    }

    println!("");
    out.sort();
    for v in out {
        println!("{v} is open")
    }
}
