#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerfEventArray,
    programs::XdpContext,
    helpers::bpf_get_smp_processor_id,
};
use core::mem;

use xdp_interceptor::PacketInfo;

#[map]
static PACKET_EVENTS: PerfEventArray<PacketInfo> = PerfEventArray::new(0);

const ETH_P_IP: u16 = 0x0800u16.to_be();
const IPPROTO_TCP: u8 = 6;

#[repr(C)]
struct EthHdr {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    ether_type: u16,
}

#[repr(C)]
struct Ipv4Hdr {
    version_ihl: u8,
    tos: u8,
    len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_addr: u32,
    dst_addr: u32,
}

#[repr(C)]
struct TcpHdr {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack_seq: u32,
    offset_res: u8,
    flags: u8,
    window: u16,
    checksum: u16,
    urg_ptr: u16,
}

/// RFC 1624 Incremental Checksum Update
/// HC' = ~(~HC + ~m + m')
#[inline(always)]
fn update_checksum(old_cksum: u16, old_val: u16, new_val: u16) -> u16 {
    let old_cksum_h = u16::from_be(old_cksum);
    let old_val_h = u16::from_be(old_val);
    let new_val_h = u16::from_be(new_val);

    let mut sum = ((!old_cksum_h) as u32) & 0xFFFF;
    sum = sum.wrapping_add(((!old_val_h) as u32) & 0xFFFF);
    sum = sum.wrapping_add(new_val_h as u32);
    
    let sum = (sum & 0xFFFF) + (sum >> 16);
    let sum = (sum & 0xFFFF) + (sum >> 16);
    
    !(sum as u16).to_be()
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + mem::size_of::<T>() > end {
        return None;
    }
    Some((start + offset) as *mut T)
}

#[xdp]
pub fn xdp_mutate(ctx: XdpContext) -> u32 {
    unsafe {
        match try_xdp_mutate(&ctx) {
            Ok(action) => action,
            Err(_) => xdp_action::XDP_PASS,
        }
    }
}

#[inline(always)]
unsafe fn try_xdp_mutate(ctx: &XdpContext) -> Result<u32, ()> {
    let eth: *mut EthHdr = ptr_at(ctx, 0).ok_or(())?;
    
    if (*eth).ether_type != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip: *mut Ipv4Hdr = ptr_at(ctx, mem::size_of::<EthHdr>()).ok_or(())?;
    if (*ip).protocol != IPPROTO_TCP {
        return Ok(xdp_action::XDP_PASS);
    }

    // IP TTL Fingerprint Erasure
    let old_ttl_word = u16::from_be_bytes([(*ip).ttl, (*ip).protocol]);
    let new_ttl = 64; 
    let new_ttl_word = u16::from_be_bytes([new_ttl, (*ip).protocol]);
    
    if (*ip).ttl != new_ttl {
        (*ip).checksum = update_checksum((*ip).checksum, old_ttl_word.to_be(), new_ttl_word.to_be());
        (*ip).ttl = new_ttl;
    }

    let ihl = ((*ip).version_ihl & 0x0F) as usize;
    let tcp_offset = mem::size_of::<EthHdr>() + (ihl << 2);
    let tcp: *mut TcpHdr = ptr_at(ctx, tcp_offset).ok_or(())?;

    // TCP Window Spoofing
    let old_win = (*tcp).window;
    let new_win = 0xFAF0u16.to_be(); 
    
    if old_win != new_win {
        (*tcp).checksum = update_checksum((*tcp).checksum, old_win, new_win);
        (*tcp).window = new_win;
    }

    // Telemetry Dispatch
    let info = PacketInfo {
        src_addr: (*ip).src_addr,
        dst_addr: (*ip).dst_addr,
        protocol: IPPROTO_TCP as u32,
        action: xdp_action::XDP_PASS as u8,
        _pad: [0, 0, 0], 
    };

    let cpu_id = bpf_get_smp_processor_id();
    let _ = PACKET_EVENTS.output(ctx, &info, cpu_id);

    Ok(xdp_action::XDP_PASS)
}

#[no_mangle]
static _LICENSE: [u8; 4] = *b"GPL\0";
