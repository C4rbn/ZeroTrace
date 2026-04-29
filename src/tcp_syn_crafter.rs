use std::mem::{self, addr_of};
use std::sync::atomic::{AtomicI32, Ordering};
use rand::Rng;

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
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

#[repr(C)]
pub struct SockAddrIn6 {
    pub family: u16,
    pub port: u16,
    pub flowinfo: u32,
    pub addr: [u8; 16],
    pub scope_id: u32,
}

#[repr(C, packed)]
struct PseudoHeaderV4 {
    src: [u8; 4],
    dst: [u8; 4],
    zero: u8,
    proto: u8,
    len: u16,
}

#[repr(C, packed)]
struct PseudoHeaderV6 {
    src: [u8; 16],
    dst: [u8; 16],
    len: u32,
    zero: [u8; 3],
    proto: u8,
}

static SOCKET_FD_V4: AtomicI32 = AtomicI32::new(-1);
static SOCKET_FD_V6: AtomicI32 = AtomicI32::new(-1);

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

pub fn create_syn_packet_v4(src_ip: [u8; 4], dst_ip: [u8; 4], dport: u16, window: u16) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut tcp_header = TcpHeader {
        sport: rng.gen_range(49152..65535).to_be(),
        dport: dport.to_be(),
        seq: rng.gen::<u32>().to_be(),
        ack: 0,
        off_res: 0x50,
        flags: 0x02,
        win: window.to_be(),
        csum: 0,
        urp: 0,
    };

    let phdr = PseudoHeaderV4 { src: src_ip, dst: dst_ip, zero: 0, proto: IPPROTO_TCP as u8, len: 20u16.to_be() };
    
    let mut tcp_csum_data = Vec::with_capacity(32);
    tcp_csum_data.extend_from_slice(unsafe { std::slice::from_raw_parts(addr_of!(phdr) as *const u8, mem::size_of::<PseudoHeaderV4>()) });
    tcp_csum_data.extend_from_slice(unsafe { std::slice::from_raw_parts(addr_of!(tcp_header) as *const u8, mem::size_of::<TcpHeader>()) });
    tcp_header.csum = internet_checksum(&tcp_csum_data).to_be();

    let mut ip_header = Ipv4Header {
        v_ihl: 0x45, tos: 0, len: 40u16.to_be(), id: rng.gen::<u16>().to_be(), off: 0x4000u16.to_be(),
        ttl: 64, pro: IPPROTO_TCP as u8, csum: 0, src: src_ip, dst: dst_ip,
    };

    ip_header.csum = internet_checksum(unsafe { std::slice::from_raw_parts(addr_of!(ip_header) as *const u8, 20) }).to_be();

    let mut packet = Vec::with_capacity(40);
    packet.extend_from_slice(unsafe { std::slice::from_raw_parts(addr_of!(ip_header) as *const u8, 20) });
    packet.extend_from_slice(unsafe { std::slice::from_raw_parts(addr_of!(tcp_header) as *const u8, 20) });
    packet
}

pub fn create_syn_packet_v6(src_ip: [u8; 16], dst_ip: [u8; 16], dport: u16, window: u16) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut tcp_header = TcpHeader {
        sport: rng.gen_range(49152..65535).to_be(),
        dport: dport.to_be(),
        seq: rng.gen::<u32>().to_be(),
        ack: 0, off_res: 0x50, flags: 0x02, win: window.to_be(), csum: 0, urp: 0,
    };

    let phdr = PseudoHeaderV6 { src: src_ip, dst: dst_ip, len: 20u32.to_be(), zero: [0; 3], proto: IPPROTO_TCP as u8 };

    let mut tcp_csum_data = Vec::with_capacity(56);
    tcp_csum_data.extend_from_slice(unsafe { std::slice::from_raw_parts(addr_of!(phdr) as *const u8, mem::size_of::<PseudoHeaderV6>()) });
    tcp_csum_data.extend_from_slice(unsafe { std::slice::from_raw_parts(addr_of!(tcp_header) as *const u8, mem::size_of::<TcpHeader>()) });
    tcp_header.csum = internet_checksum(&tcp_csum_data).to_be();

    let mut packet = Vec::with_capacity(20);
    packet.extend_from_slice(unsafe { std::slice::from_raw_parts(addr_of!(tcp_header) as *const u8, 20) });
    packet
}

pub fn send_raw_packet_v4(dst_ip: [u8; 4], packet: &[u8]) -> Result<(), std::io::Error> {
    let mut fd = SOCKET_FD_V4.load(Ordering::Relaxed);
    if fd == -1 {
        unsafe {
            fd = libc::socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
            if fd < 0 { return Err(std::io::Error::last_os_error()); }
            let on: i32 = 1;
            libc::setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on as *const _ as *const libc::c_void, 4);
        }
        if let Err(existing_fd) = SOCKET_FD_V4.compare_exchange(-1, fd, Ordering::SeqCst, Ordering::SeqCst) {
            unsafe { libc::close(fd) };
            fd = existing_fd;
        }
    }

    let addr = SockAddrIn { family: AF_INET as u16, port: 0, addr: dst_ip, zero: [0; 8] };
    let res = unsafe { libc::sendto(fd, packet.as_ptr() as *const libc::c_void, packet.len(), 0, &addr as *const _ as *const libc::sockaddr, mem::size_of::<SockAddrIn>() as u32) };
    if res < 0 { return Err(std::io::Error::last_os_error()); }
    Ok(())
}

pub fn send_raw_packet_v6(dst_ip: [u8; 16], packet: &[u8]) -> Result<(), std::io::Error> {
    let mut fd = SOCKET_FD_V6.load(Ordering::Relaxed);
    if fd == -1 {
        unsafe {
            fd = libc::socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
            if fd < 0 { return Err(std::io::Error::last_os_error()); }
        }
        if let Err(existing_fd) = SOCKET_FD_V6.compare_exchange(-1, fd, Ordering::SeqCst, Ordering::SeqCst) {
            unsafe { libc::close(fd) };
            fd = existing_fd;
        }
    }

    let addr = SockAddrIn6 { family: AF_INET6 as u16, port: 0, flowinfo: 0, addr: dst_ip, scope_id: 0 };
    let res = unsafe { libc::sendto(fd, packet.as_ptr() as *const libc::c_void, packet.len(), 0, &addr as *const _ as *const libc::sockaddr, mem::size_of::<SockAddrIn6>() as u32) };
    if res < 0 { return Err(std::io::Error::last_os_error()); }
    Ok(())
}
