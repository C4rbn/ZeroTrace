#![allow(unsafe_code)]
#![allow(dead_code)]

use std::mem;
use std::ptr::addr_of;

// --- FFI Bindings ---
extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    fn setsockopt(fd: i32, level: i32, optname: i32, optval: *const i32, optlen: u32) -> i32;
    fn sendto(
        fd: i32, 
        buf: *const u8, 
        len: usize, 
        flags: i32, 
        addr: *const SockAddrIn, 
        len_a: u32
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

#[repr(C, packed)]
pub struct FullPacket {
    pub ip: Ipv4Header,
    pub tcp: TcpHeader,
}

#[repr(C, packed)]
struct Phdr {
    src: [u8; 4],
    dst: [u8; 4],
    zero: u8,
    proto: u8,
    len: u16,
    tcp: TcpHeader,
}

pub struct Config {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub sport: u16,
    pub dport: u16,
    pub window: u16,
}

static mut CACHED_SOCKET: i32 = -1;

/// Calculates the internet checksum. 
/// Utilizes AVX2 SIMD instructions if the hardware supports it and data is sufficient.
#[inline(always)]
pub unsafe fn calculate_checksum(data: *const u8, len: usize) -> u16 {
    use std::arch::x86_64::*;

    if is_x86_feature_detected!("avx2") && len >= 32 {
        let mut sum_vec = _mm256_setzero_si256();
        let block = _mm256_loadu_si256(data as *const __m256i);
        
        sum_vec = _mm256_add_epi64(sum_vec, _mm256_sad_epu8(block, _mm256_setzero_si256()));

        let sum0 = _mm256_extract_epi64(sum_vec, 0) as u64;
        let sum1 = _mm256_extract_epi64(sum_vec, 1) as u64;
        let sum2 = _mm256_extract_epi64(sum_vec, 2) as u64;
        let sum3 = _mm256_extract_epi64(sum_vec, 3) as u64;

        let total_sum: u64 = sum0 + sum1 + sum2 + sum3;
        let mut res_sum: u32 = (total_sum as u32) + (total_sum >> 32) as u32;

        while (res_sum >> 16) != 0 {
            res_sum = (res_sum & 0xFFFF) + (res_sum >> 16);
        }
        !(res_sum as u16)
    } else {
        let mut sum: u32 = 0;
        let ptr = data as *const u16;
        for i in 0..(len / 2) {
            sum += u16::from_be(std::ptr::read_unaligned(ptr.add(i))) as u32;
        }
        if len % 2 == 1 {
            sum += (*data.add(len - 1) as u32) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

pub fn create_syn_packet(cfg: &Config) -> Vec<u8> {
    unsafe {
        let mut pkt = FullPacket {
            ip: Ipv4Header {
                v_ihl: 0x45,
                tos: 0,
                len: (40u16).to_be(),
                id: 0x1337u16.to_be(),
                off: 0x4000u16.to_be(),
                ttl: 64,
                pro: 6,
                csum: 0,
                src: cfg.src_ip,
                dst: cfg.dst_ip,
            },
            tcp: TcpHeader {
                sport: cfg.sport.to_be(),
                dport: cfg.dport.to_be(),
                seq: 0xDEADBEEF,
                ack: 0,
                off_res: 0x50,
                flags: 0x02,
                win: cfg.window.to_be(),
                csum: 0,
                urp: 0,
            },
        };

        let phdr = Phdr {
            src: cfg.src_ip,
            dst: cfg.dst_ip,
            zero: 0,
            proto: 6,
            len: (20u16).to_be(),
            tcp: pkt.tcp,
        };

        pkt.tcp.csum = calculate_checksum(addr_of!(phdr) as *const u8, mem::size_of::<Phdr>());
        pkt.ip.csum = calculate_checksum(addr_of!(pkt.ip) as *const u8, 20);

        let p_ptr = addr_of!(pkt) as *const u8;
        std::slice::from_raw_parts(p_ptr, 40).to_vec()
    }
}

pub fn send_raw_packet(dst_ip: [u8; 4], packet: &[u8]) -> Result<(), std::io::Error> {
    unsafe {
        if CACHED_SOCKET == -1 {
            CACHED_SOCKET = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
            if CACHED_SOCKET < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let on: i32 = 1;
            setsockopt(CACHED_SOCKET, IPPROTO_IP, IP_HDRINCL, &on, 4);
        }

        let addr = SockAddrIn {
            family: AF_INET as u16,
            port: 0,
            addr: dst_ip,
            zero: [0; 8],
        };

        let res = sendto(
            CACHED_SOCKET,
            packet.as_ptr(),
            packet.len(),
            0,
            &addr,
            16,
        );

        if res < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}
