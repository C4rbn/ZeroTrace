#![allow(unsafe_code)]

use boring::ssl::{SslConnector, SslMethod, SslOptions, SslVersion};
use boring_sys as ffi;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

#[allow(dead_code)]
#[inline(always)]
fn hardware_rand_u64() -> u64 {
    let mut val: u64 = 0;

    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("rdrand") {
            unsafe {
                core::arch::asm!(
                    "2:",
                    "rdrand {0}",
                    "jnc 2b",
                    out(reg) val,
                    options(nomem, nostack)
                );
            }
            return val;
        }
    }

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[allow(dead_code)]
pub fn peak_grease_u16() -> u16 {
    let val = (hardware_rand_u64() & 0x0F) as u16;
    (val << 12) | (0x0A00) | (val << 4) | 0x0A
}

pub fn build_stealth_connector() -> Result<SslConnector, boring::error::ErrorStack> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;

    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    unsafe {
        let ctx_ptr = builder.as_ptr();
        ffi::SSL_CTX_set_grease_enabled(ctx_ptr, 1);
        ffi::SSL_CTX_set_permute_extensions(ctx_ptr, 1);
    }

    builder.set_cipher_list(
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
    )?;

    builder.set_options(SslOptions::NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
    builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;

    Ok(builder.build())
}

pub fn execute_stealth_request(host: &str) {
    let connector = match build_stealth_connector() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[!] Builder Error: {:?}", e);
            return;
        }
    };

    let stream = match TcpStream::connect((host, 443)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[!] Network Error: {:?}", e);
            return;
        }
    };

    match connector.connect(host, stream) {
        Ok(mut tls) => {
            let request = format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nConnection: close\r\n\r\n",
                host
            );
            let _ = tls.write_all(request.as_bytes());
            let mut res = [0u8; 1024];
            let _ = tls.read(&mut res);
            println!("[SUCCESS] Native Stealth Handshake Completed.");
        }
        Err(e) => eprintln!("[FAIL] Handshake Error: {:?}", e),
    }
}
