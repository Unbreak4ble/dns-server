
#[derive(Debug)]
pub enum IpAddr {
    Ipv4(u8, u8, u8, u8),
    Ipv6(u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u8),
    Null,
}

pub fn hex_to_int(hex: &String) -> u8 {
    let mut nibble: [u8; 2] = [0,0];
    let mut i=0;
    for ch in hex.chars() {
        let ch = ch as u8;
        nibble[i] = match ch {
            0x30..=0x39 => ch - 0x30,
            0x61..=0x66 => ch - 0x61 + 0xa,
            _ => 0,
        };
        i+=1;
    }
    (nibble[0] << 4) | nibble[1]
}

pub fn string_to_ip(ip: String, typ: u16) -> Result<IpAddr, &'static str> {
    let mut res: IpAddr = IpAddr::Null;
    if typ == 1 {
        let mut ipv4:[u8; 4] = [0; 4];
        let mut i=0;
        let masks = ip.replace("\"", "");
        let masks = masks.split('.');
        if masks.clone().count() == 4 {
            for mask in masks {
                ipv4[i] = mask.parse::<u8>().unwrap();
                i+=1;
            }
            res = IpAddr::Ipv4(ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
        }
    } else if typ == 0x1c {
        let mut ipv6:[u8; 16] = [0; 16];
        let mut i=1;
        let mut j=0;
        let masks = ip.replace("\"", "");
        let masks = masks.split(':');
        if masks.clone().count() > 8 {
            return Err("ipv6 overflows");
        }else if masks.clone().count() < 8 {
            return Err("ipv6 incomplete. Need to be 16 bytes. Ex: 1111:2222:3333:4444:5555:6666:7777:8888");
        }
        for mask in masks {
            let mut hex = String::from("");
            for ch in mask.chars() {
                hex.push(ch);
                if j >= 16 {
                    return Err("ipv6 overflows");
                }else if i%2 == 0 { 
                    ipv6[j] = hex_to_int(&hex);
                    hex=String::from("");
                    j+=1;
                    i=0;
                }
                i+=1;
            }
            i=1;
        }
        res = IpAddr::Ipv6(ipv6[0], ipv6[1], ipv6[2], ipv6[3], ipv6[4], ipv6[5], ipv6[6], ipv6[7], ipv6[8], ipv6[9], ipv6[10], ipv6[11], ipv6[12], ipv6[13], ipv6[14], ipv6[15]);
    }
    Ok(res)
}

pub fn ipvx_to_array(ipvx: IpAddr, arr: &mut Vec<u8>) {
    match ipvx {
        IpAddr::Ipv4(a,b,c,d) => {
            arr.push(a);
            arr.push(b);
            arr.push(c);
            arr.push(d);
        },
        IpAddr::Ipv6(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p) => {
            arr.push(a);
            arr.push(b);
            arr.push(c);
            arr.push(d);
            arr.push(e);
            arr.push(f);
            arr.push(g);
            arr.push(h);
            arr.push(i);
            arr.push(j);
            arr.push(k);
            arr.push(l);
            arr.push(m);
            arr.push(n);
            arr.push(o);
            arr.push(p);
        },
        IpAddr::Null => {}
    }
}

pub fn ipvx_to_string(ip: IpAddr) -> String {
    let mut arr = String::from("");
    match ip {
        IpAddr::Ipv4(a,b,c,d) => {
            arr.push_str(&format!("{}", a.to_string()));
            arr.push('.');
            arr.push_str(&format!("{}", b.to_string()));
            arr.push('.');
            arr.push_str(&format!("{}", c.to_string()));
            arr.push('.');
            arr.push_str(&format!("{}", d.to_string()));
        },
        IpAddr::Ipv6(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p) => {
            arr.push_str(&format!("{}", a.to_string()));
            arr.push_str(&format!("{}", b.to_string()));
            arr.push(':');
            arr.push_str(&format!("{}", c.to_string()));
            arr.push_str(&format!("{}", d.to_string()));
            arr.push(':');
            arr.push_str(&format!("{}", e.to_string()));
            arr.push_str(&format!("{}", f.to_string()));
            arr.push(':');
            arr.push_str(&format!("{}", g.to_string()));
            arr.push_str(&format!("{}", h.to_string()));
            arr.push(':');
            arr.push_str(&format!("{}", i.to_string()));
            arr.push_str(&format!("{}", j.to_string()));
            arr.push(':');
            arr.push_str(&format!("{}", k.to_string()));
            arr.push_str(&format!("{}", l.to_string()));
            arr.push(':');
            arr.push_str(&format!("{}", m.to_string()));
            arr.push_str(&format!("{}", n.to_string()));
            arr.push(':');
            arr.push_str(&format!("{}", o.to_string()));
            arr.push_str(&format!("{}", p.to_string()));
        },
        IpAddr::Null => {}
    }
    arr
}
