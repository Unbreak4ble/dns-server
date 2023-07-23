use crate::net as net;
use serde_json::{Number, Value};

static mut _json: Value = Value::Null;

pub fn loadJson(path: String) {
    let content = std::fs::read_to_string(&path).unwrap();
    let json = serde_json::from_str::<Value>(&content).unwrap();
    match json {
        ref Value => {
            unsafe {
                _json = json.clone();
            }
        },
        _ => panic!("cannot read json."),
    }
}

pub fn requestNSList() -> Option<Vec<net::IpAddr>> {
    let mut content = std::fs::read_to_string("nameservers.txt").unwrap_or(String::from(""));
    content.push('\0');
    let mut nameservers: Vec<net::IpAddr> = Vec::new();
    let mut address: Vec<u8> = Vec::new();
    let mut num: u8 = 0;
    let mut idx = 0;
    let mut n=0;
    for ch in content.clone().chars() {
        match ch {
            '\n' | '\0' => {
                address.push(num);
                if address.len() == 4 {
                    nameservers.push(net::IpAddr::Ipv4(address[0], address[1], address[2], address[3]));
                }else if idx > 0 {
                    println!("invalid address at line {}", n);
                    break;
                }
                address = Vec::new();
                idx = 0;
                num = 0;
                n+=1;
            },
            '.' => {
                address.push(num);
                idx=0;
                num = 0;
            },
            '0'..='9' => {
                num = num * 10 + (ch as u8) - 0x30;
                idx+=1;
            },
            _ => { println!("invalid address at line {}", n); break;}
        }
    }
    if nameservers.len() > 0 { Some(nameservers) } else { None }
}

pub fn getGenericAddress() -> Result<Vec<net::IpAddr>, &'static str> {
    let ask = String::from("*");
    let mut address4 = requestAddresses(&ask, 1).unwrap_or(Vec::new());
    let mut address6 = requestAddresses(&ask, 28).unwrap_or(Vec::new());
    address4.append(&mut address6);
    Ok(address4)
}

pub fn requestAddresses(dmn: &String, typ: u16) -> Result<Vec<net::IpAddr>, &'static str> {
    let mut content: Value = Value::Null;
    unsafe { content = _json.clone(); }
    if content != Value::Null {
        for (key, value) in content.as_object().unwrap() {
            if key == dmn {
                let addresses = value.as_array().unwrap().to_vec();
                let mut IpList: Vec<net::IpAddr> = Vec::new();
                for addr in addresses.into_iter() {
                    let Value::Object(obj_addr) = addr else { panic!("cannot parse object"); };
                    if obj_addr["type"].as_u64().unwrap_or(1) as u16 == typ {
                        let addrs = net::string_to_ip(obj_addr["address"].to_string(), typ).unwrap();
                        IpList.push(addrs);
                    }
                }
                return  Ok(IpList);
            }
        }
    }
    Err("domain not found")
}
