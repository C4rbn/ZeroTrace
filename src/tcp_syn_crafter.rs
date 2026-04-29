use std::mem;
use std::ptr::addr_of;
use std::sync::atomic::{AtomicI32, Ordering};
use rand::Rng;

unsafe extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn setsockopt(fd: i32, level: i32, optname: i32, optval: *const i32, optlen: u32) -> i32;
    fn sendto(
        fd: i32,
        buf: *const u8,
        len: usize,
        flags: i32,
        addr: *const SockAddrIn,
        len_a: u32,
    ) -> isize;
}

const AF_INET: i32 = 2;
const SOCK_RAW: i32 = 3;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_IP: i32 = 0;
const IP_HDRINCL: i32 = 3;

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct Ipv4Header {
    pub v_ihl: u8,
    pub tos: u8,
    pub len: u16,
    pub id: u16,
    pub off: u16,
    pub ttl: u8,
    pub pro: u8,
    pub csum: u16,
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct TcpHeader {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub off_res: u8,
    pub flags: u8,
    pub win: u16,
    pub csum: u16,
    pub urp: u16,
}

#[repr(C)]
pub struct SockAddrIn {
    pub family: u16,
    pub port: u16,
    pub addr: [u8; 4],
    pub zero: [u8; 8],
}

#[allow(dead_code)]
#[repr(C, packed)]
pub struct FullPacket {
    pub ip: Ipv4Header,
    pub tcp: TcpHeader,
}

#[repr(C, packed)]
struct PseudoHeader {
    src: [u8; 4],
    dst: [u8; 4],
    zero: u8,
    proto: u8,
    len: u16,
}

pub struct Config {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub dport: u16,
    pub window: u16,
}

static SOCKET_FD: AtomicI32 = AtomicI32::new(-1);

pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);

    for chunk in chunks.by_ref() {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum = sum.wrapping_add(word as u32);
    }

    if let Some(&last) = chunks.remainder().first() {
        sum = sum.wrapping_add((last as u32) << 8);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

pub fn create_syn_packet(cfg: &Config) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let seq_num = rng.gen::<u32>();
    let src_port: u16 = rng.gen_range(49152..65535);

    let mut tcp_header = TcpHeader {
        sport: src_port.to_be(),
        dport: cfg.dport.to_be(),
        seq: seq_num.to_be(),
        ack: 0,
        off_res: 0x50,
        flags: 0x02,
        win: cfg.window.to_be(),
        csum: 0,
        urp: 0,
    };

    let phdr = PseudoHeader {
        src: cfg.src_ip,
        dst: cfg.dst_ip,
        zero: 0,
        proto: IPPROTO_TCP as u8,
        len: (20u16).to_be(),
    };

    let mut tcp_checksum_data = Vec::with_capacity(32);
    tcp_checksum_data.extend_from_slice(unsafe {
        std::slice::from_raw_parts(addr_of!(phdr) as *const u8, mem::size_of::<PseudoHeader>())
    });
    tcp_checksum_data.extend_from_slice(unsafe {
        std::slice::from_raw_parts(addr_of!(tcp_header) as *const u8, mem::size_of::<TcpHeader>())
    });

    tcp_header.csum = internet_checksum(&tcp_checksum_data).to_be();

    let mut ip_header = Ipv4Header {
        v_ihl: 0x45,
        tos: 0,
        len: (40u16).to_be(),
        id: rng.gen::<u16>().to_be(),
        off: 0x4000u16.to_be(),
        ttl: 64,
        pro: IPPROTO_TCP as u8,
        csum: 0,
        src: cfg.src_ip,
        dst: cfg.dst_ip,
    };

    ip_header.csum = internet_checksum(unsafe {
        std::slice::from_raw_parts(addr_of!(ip_header) as *const u8, 20)
    })
    .to_be();

    let mut packet = Vec::with_capacity(40);
    packet.extend_from_slice(unsafe {
        std::slice::from_raw_parts(addr_of!(ip_header) as *const u8, 20)
    });
    packet.extend_from_slice(unsafe {
        std::slice::from_raw_parts(addr_of!(tcp_header) as *const u8, 20)
    });

    packet
}

pub fn send_raw_packet(dst_ip: [u8; 4], packet: &[u8]) -> Result<(), std::io::Error> {
    let mut fd = SOCKET_FD.load(Ordering::Relaxed);

    if fd == -1 {
        unsafe {
            fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let on: i32 = 1;
            setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, 4);
        }

        match SOCKET_FD.compare_exchange(-1, fd, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => {}
            Err(existing_fd) => {
                unsafe { libc::close(fd) };
                fd = existing_fd;
            }
        }
    }

    let addr = SockAddrIn {
        family: AF_INET as u16,
        port: 0,
        addr: dst_ip,
        zero: [0; 8],
    };

    let res = unsafe { sendto(fd, packet.as_ptr(), packet.len(), 0, &addr, 16) };

    if res < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
