#![no_std]

/// IPv4 packet metadata for telemetry synchronization.
/// Structured with 8-byte alignment to ensure compatibility across
/// various kernel architectures and prevent EINVAL during map initialization.
#[repr(C, align(8))] 
#[derive(Clone, Copy)]
pub struct PacketInfo {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub protocol: u32,
    pub action: u8,
    pub _pad: [u8; 3], 
}

impl PacketInfo {
    /// Returns the source address in host byte order.
    #[inline(always)]
    pub fn fast_host_src_addr(&self) -> u32 {
        u32::from_be(self.src_addr)
    }

    /// Returns the destination address in host byte order.
    #[inline(always)]
    pub fn fast_host_dst_addr(&self) -> u32 {
        u32::from_be(self.dst_addr)
    }
}

unsafe impl Send for PacketInfo {}
unsafe impl Sync for PacketInfo {}

/// Standard XDP action codes for telemetry reporting.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XdpAction {
    Aborted = 0,
    Drop    = 1,
    Pass    = 2,
    Tx      = 3,
    Redirect = 4,
}

impl XdpAction {
    #[inline(always)]
    pub fn from_u8(v: u8) -> Self {
        if v > 4 { 
            XdpAction::Aborted 
        } else { 
            unsafe { core::mem::transmute(v) } 
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            XdpAction::Aborted => "ABORTED",
            XdpAction::Drop => "DROP",
            XdpAction::Pass => "PASS",
            XdpAction::Tx => "TX",
            XdpAction::Redirect => "REDIRECT",
        }
    }
}

/// Static assertion to ensure 16-byte structure size at compile time.
const _: () = assert!(core::mem::size_of::<PacketInfo>() == 16);

#[cfg(all(not(test), target_os = "none"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
