use std::net::UdpSocket as udp;
use crate::dns::{DNS_PACKET, DNS_RR, decodeContent};
use crate::domain_handler::{requestAddresses, requestNSList, getGenericAddress, loadJson};
use crate::net::{IpAddr, hex_to_int, string_to_ip, ipvx_to_array, ipvx_to_string};

const _PORT:&str = "53";
const _DOMAINS_PATH:&str = "./domains.json";

fn makeNXDomain(packet: &mut DNS_PACKET) {
    packet.rcode = 3;
    packet.ancount = 0;
    packet.nscount = 1;
    println!("called");
    let id = packet.newAuthority();
    let authority = &mut packet.authority[id];
    let bytes: [u8; 34] = [0x3, 0x61, 0x62, 0x63, 0x2, 0x65, 0x66, 0x00, 0x03, 0x64, 0x6e, 0x73, 0xc0, 0x2f, 0x89, 0xeb, 0x4d, 0xdf, 0x00, 0x00, 0x27, 0x10, 0x00, 0x00, 0x09, 0x60, 0x00, 0x09, 0x3a, 0x80, 0x00, 0x00, 0x07, 0x08];
    authority.qpointer = 0xc00c;
    authority.qtype = 6;
    authority.qclass = 1;
    authority.ttl = 0x000006fe;
    authority.rdlength = 34;
    for b in bytes { authority.rdata.push(b); }
}

async fn makeAnswer(packet: &mut DNS_PACKET, generic: bool) {
    let domain = &packet.qname_domain;
    let db = if !generic { requestAddresses(&domain, packet.qtype) } else { getGenericAddress() };
    if let Ok(addresses) = db {
        packet.qr = 1;
        packet.rd = 1;
        packet.z = 0x8;
        for address in addresses.into_iter() {
            let id = packet.newAnswer();
            let mut answer: Vec<u8> = Vec::new();
            packet.ancount+=1;
            answer.push(0xc0); 
            answer.push(0x0c);
            answer.push(((packet.qtype & 0xFF00) >> 8) as u8);
            answer.push((packet.qtype & 0xFF) as u8);
            answer.push(((packet.qclass & 0xFF00) >> 8) as u8);
            answer.push((packet.qclass & 0xFF) as u8);
            answer.push(0);
            answer.push(0);
            answer.push(0);
            answer.push(0xff);
            answer.push(0);
            match address {
                IpAddr::Ipv4(..) if packet.qtype == 1 => {
                    answer.push(4);
                    ipvx_to_array(address, &mut answer);
                },
                IpAddr::Ipv6(..) if packet.qtype == 0x1c => {
                    answer.push(16);
                    ipvx_to_array(address, &mut answer);
                },
                IpAddr::Null | IpAddr::Ipv6(..) | IpAddr::Ipv4(..) => {
                    packet.ancount = 0;
                    continue;
                },
            }
            packet.answer[id].decode(answer);
        }
    }else if !generic {
        let response = request_from_nameserver(packet.encode()).await;
        if let Ok(buffer) = response {
            *packet = Default::default();
            packet.decode(&buffer);
        }else if let Err(error) = response {
            println!("error from response: {:?}", error);
        }
    }
}

pub async fn request_from_nameserver(buffer: Vec<u8>) -> Result<Vec<u8>, std::io::Error> {
    let socket = udp::bind("0.0.0.0:0").expect("cannot bind");
    let nameservers_op = requestNSList();
    if let Some(nameservers) = nameservers_op {
        for nameserv in nameservers.into_iter() {
            let mut buff: [u8; 65536] = [0; 65536];
            if let IpAddr::Ipv4(a,b,c,d) = nameserv {
                let mut ip = ipvx_to_string(nameserv);
                socket.connect(ip+":53").unwrap_or_default();
                let status = socket.send(&buffer as &[u8]);
                if let Ok(..) = status {
                    let (sz, src) = socket.recv_from(&mut buff)?;
                    return Ok(buff[0..sz].to_vec())
                }else{continue;}
            }
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::Other, "no nameserver found"))
}

pub async fn run_server(ip: String) -> Result<(), std::io::Error> {
    let socket = udp::bind(ip+":"+_PORT).expect("cannot bind port");
    let mut buff:[u8; 65536] = [0; 65536];
    loadJson(String::from(_DOMAINS_PATH));
    println!("running");
    loop {
        let (size, src_sock) = socket.recv_from(&mut buff)?;
        let mut packet_decoded: DNS_PACKET = Default::default();
        packet_decoded.decode(&buff[0..size].to_vec());
        makeAnswer(&mut packet_decoded, false).await;
        if packet_decoded.ancount == 0 {
            packet_decoded = Default::default();
            packet_decoded.decode(&buff[0..size].to_vec());
            makeAnswer(&mut packet_decoded, true).await;
        }
        let mut pkt = packet_decoded.encode();
        let mut buff: &[u8] = &mut pkt;
        socket.send_to(buff, &src_sock)?;
    };
    Ok(())
}
