// ... (keep previous imports and structs)

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

    // FIX: Use dynamic size_of for cross-arch compatibility
    let addr_len = std::mem::size_of::<SockAddrIn>() as u32;
    let res = unsafe { sendto(fd, packet.as_ptr(), packet.len(), 0, &addr, addr_len) };

    if res < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
