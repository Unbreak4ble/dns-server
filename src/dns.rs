#[derive(Clone)]
pub struct DNS_RR {
    pub qpointer: u16, //pointer of 2 bytes to compress qname
    pub qtype: u16,
    pub qclass: u16,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: Vec<u8>,
}

pub struct DNS_PACKET {
//Header fields
    pub id: u16, // 2 bytes
    pub qr: u8, // 1 bit
    pub opcode: u8, // 1 nibble (4 bits)
    pub aa: u8, // 1 bit
    pub tc: u8, // 1 bit
    pub rd: u8, // 1 bit
    pub ra: u8, // 1 bit
    pub z: u8, // 3 bits
    pub rcode: u8, // 1 nibble
    pub qdcount:u16, // 2 bytes
    pub ancount:u16, // 2 bytes
    pub nscount:u16, // 2 bytes
    pub arcount:u16, // 2 bytes
//Question fields
    pub qname_length: u8, // not implemented for packet.
    pub qname: String, // x bytes (variable)
    pub qname_domain: String, // not implemented for packet.
    pub qtype: u16, // 2 bytes
    pub qclass: u16, // 2 bytes
//Answer fields
    pub answer: Vec<DNS_RR>,
//Authority
    pub authority: Vec< DNS_RR>, 
//Additional
    pub additional: Vec<DNS_RR>,
}

impl Default for DNS_RR {
    fn default() -> Self {
        Self {
            qpointer: 0,
            qtype: 0,
            qclass: 0,
            ttl: 0,
            rdlength: 0,
            rdata: Vec::new(),
        }
    }
}

impl DNS_PACKET {
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        /* HEADER */
        buffer.push(((self.id & 0xFF00) >> 8) as u8);
        buffer.push((self.id & 0xFF) as u8);

        buffer.push((self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | (self.tc << 1) | (self.rd));
        buffer.push((self.ra << 7) | (self.z << 4) | (self.rcode));

        buffer.push(((self.qdcount & 0xFF00) >> 8) as u8);
        buffer.push((self.qdcount & 0xFF) as u8);

        buffer.push(((self.ancount & 0xFF00) >> 8) as u8);
        buffer.push((self.ancount & 0xFF) as u8);

        buffer.push(((self.nscount & 0xFF00) >> 8) as u8);
        buffer.push((self.nscount & 0xFF) as u8);

        buffer.push(((self.arcount & 0xFF00) >> 8) as u8);
        buffer.push((self.arcount & 0xFF) as u8);

        /* QUESTION */
        if self.qdcount > 0 {
            for ch in self.qname.chars() { buffer.push(ch as u8); }
            buffer.push(0);
        
            buffer.push(((self.qtype & 0xFF00) >> 8) as u8);
            buffer.push((self.qtype & 0xFF) as u8);

            buffer.push(((self.qclass & 0xFF00) >> 8) as u8);
            buffer.push((self.qclass & 0xFF) as u8);
        }

        /* ANSWER */
        if self.ancount > 0 {
            for rr in self.answer.clone().into_iter() {
                for b in rr.encode() {
                    buffer.push(b);
                }
            }
        }

        /* authority */
        if self.nscount > 0 {
            for rr in self.authority.clone().into_iter() {
                for b in rr.encode() {
                    buffer.push(b);
                }
            }
        }

        /* additional */
        if self.arcount > 0 {
            for rr in self.additional.clone().into_iter() {
                for b in rr.encode() {
                    buffer.push(b);
                }
            }
        }

        buffer
    }
    pub fn decode(&mut self, buffer: &Vec<u8>) {
        let mut idx=0;
        let mut neededIdx=0;
       
        /* HEADER 12 bytes */
        for byte in buffer {
            if idx == 1 {
                self.id = ((buffer[idx-1] as u16) << 8) | buffer[idx] as u16;
            }else if idx == 3 {
                self.qr = buffer[idx-1] >> 7;
                self.opcode = (buffer[idx-1] & 0x78) >> 3;
                self.aa = (buffer[idx-1] & 0x4) >> 2;
                self.tc = (buffer[idx-1] & 0x2) >> 1;
                self.rd = buffer[idx-1] & 0x1;
                self.ra = buffer[idx] >> 7;
                self.z = (buffer[idx] & 0x70) >> 4;
                self.rcode = buffer[idx] & 0xf;
            }else if idx == 5 {
                self.qdcount = ((buffer[idx-1] as u16) << 8) | buffer[idx] as u16;
            }else if idx == 7 {
                self.ancount = ((buffer[idx-1] as u16) << 8) | buffer[idx] as u16;
            }else if idx == 9 {
                self.nscount = ((buffer[idx-1] as u16) << 8) | buffer[idx] as u16;
            }else if idx == 11 {
                self.arcount = ((buffer[idx-1] as u16) << 8) | buffer[idx] as u16;
            }else if idx > 11 { break; }
            idx+=1;
        }

        /* Question */
        for qd in 0..self.qdcount {
            let decoded = decodeContent(buffer[idx..].to_vec());
            if let Some((content, stop)) = decoded {
                for c in content.into_iter() {
                    self.qname_domain.push(c as char);
                }
                for c in buffer[idx..(idx+(stop as usize))].into_iter() {
                    self.qname.push(*c as char);
                }
                let mut i=0;
                for a in buffer[(1+idx+(stop as usize))..].into_iter() {
                    if i == 1 {
                        self.qtype = ((buffer[1+idx+stop as usize+i-1] as u16) << 8) | *a as u16;
                    }else if i == 3 {
                        self.qclass = ((buffer[1+idx+stop as usize+i-1] as u16) << 8) | *a as u16;
                    }else if i > 3 { i+=1; break; }
                    i+=1;
                }
                idx+=stop as usize + i;
            }else{ break; }
        }
        
        /* Answer */
        for qd in 0..self.ancount {
            let id = self.newAnswer();
            idx+=self.answer[id].decode(buffer[idx..].to_vec());
        }

        /* Authority */
        for qd in 0..self.nscount {
            let id = self.newAuthority();
            idx+=self.authority[id].decode(buffer[idx..].to_vec());           
        }

        /* Additional */
        for qd in 0..self.arcount {
            let id = self.newAdditional();
            idx+=self.additional[id].decode(buffer[idx..].to_vec());
        }
    }
    pub fn newAnswer(&mut self) -> usize {
        self.answer.push(Default::default());
        self.answer.len()-1
    }
    pub fn newAuthority(&mut self) -> usize {
        self.authority.push(Default::default());
        self.authority.len()-1
    }
    pub fn newAdditional(&mut self) -> usize {
        self.additional.push(Default::default());
        self.additional.len()-1
    }
}

impl DNS_RR {
    pub fn encode(&self) -> Vec<u8> {
        let mut vector: Vec<u8> = Vec::new();
        vector.push((self.qpointer >> 8) as u8);
        vector.push(self.qpointer as u8);

        vector.push((self.qtype >> 8) as u8);
        vector.push(self.qtype as u8);

        vector.push((self.qclass >> 8) as u8);
        vector.push(self.qclass as u8);

        vector.push((self.ttl >> 24) as u8);
        vector.push((self.ttl >> 16) as u8);
        vector.push((self.ttl >> 8) as u8);
        vector.push(self.ttl as u8);

        vector.push((self.rdlength >> 8) as u8);
        vector.push((self.rdlength) as u8);

        for b in self.rdata.clone().into_iter() { vector.push(b); }

        vector
    }
    pub fn decode(&mut self, buffer: Vec<u8>) -> usize {
        for i in 0..buffer.len() {
            if i == 1 {
                self.qpointer = ((buffer[i-1] as u16) << 8) | buffer[i] as u16;
            }else if i == 3 {
                self.qtype = ((buffer[i-1] as u16) << 8) | buffer[i] as u16;
            }else if i == 5 {
                self.qclass = ((buffer[i-1] as u16) << 8) | buffer[i] as u16;
            }else if i == 9 {
                self.ttl = ((buffer[i-3] as u32) << 24) | ((buffer[i-2] as u32) << 16) | ((buffer[i-1] as u32) << 8) | buffer[i] as u32;
            }else if i == 11 {
                self.rdlength = ((buffer[i-1] as u16) << 8) | buffer[i] as u16;
                let some = decodeContent(buffer[i..].to_vec());
                if let Some((content, idx)) = some {
                    for c in &buffer[(i+1)..(i+idx as usize)] {
                        self.rdata.push(*c);
                    }
                    return i+idx as usize;
                }else{ println!("None returned"); }
                break;
            }
        }
        0
    }
}

impl Default for DNS_PACKET {
    fn default() -> Self {
        Self {
            id:0,
            qr:0,
            opcode:0,
            aa:0,
            tc:0,
            rd:0,
            ra:0,
            z:0,
            rcode: 0,
            qdcount:0,
            ancount:0,
            nscount: 0,
            arcount: 0,
            qname_length: 0,
            qname: String::new(),
            qname_domain: String::new(),
            qtype: 0,
            qclass: 0,
            answer: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        }
    }
}

impl std::fmt::Debug for DNS_PACKET  {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("DNS_PACKET")
        .field("id", &self.id)
        .field("qr", &self.qr)
        .field("opcode", &self.opcode)
        .field("aa", &self.aa)
        .field("tc", &self.tc)
        .field("rd", &self.rd)
        .field("ra", &self.ra)
        .field("z", &self.z)
        .field("rcode", &self.rcode)
        .field("qdcount", &self.qdcount)
        .field("ancount", &self.ancount)
        .field("nscount", &self.nscount)
        .field("arcount", &self.arcount)
        .field("qname_length", &self.qname_length)
        .field("qname_domain", &self.qname_domain)
        .field("qtype", &self.qtype)
        .field("qclass", &self.qclass)
        .finish()
    }
}

pub fn decodeContent(buffer: Vec<u8>) -> Option<(Vec<u8>, u16)> {
        let mut idx = 0;
        let mut idx2:u16 = 0;
        let mut size_set: u8=0;
        let mut content: Vec<u8> = Vec::new();
        for ch in &buffer {
            if idx == 0 && size_set as usize > buffer.len() - idx2 as usize { return None; }
            if idx < size_set as usize { idx+=1; }
            else if *ch == b'\0' { break; }
            else if *ch & 0xc0 == 0xc0 { break; }
            else { if idx > 0 { content.push('.' as u8); } idx=0; idx2+=1; size_set = *ch; continue; }
            content.push(*ch);
            idx2+=1;
        }
        Some((content, idx2))
}
