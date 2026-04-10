//! VM Detection Module
//!
//! Techniques:
//! - CPUID hypervisor bit check
//! - Registry VM keys (VirtualBox, VMware, Hyper-V)
//! - MAC address OUI prefixes
//!
//! Detection artifacts:
//! - ETW: CPUID instruction
//! - Sysmon: Registry access to VM-related keys
//! - Network: Check for VM MAC prefixes

use super::AnalysisEnvironment;

/// Known VM MAC OUI prefixes (first 3 bytes)
const VM_MAC_PREFIXES: &[[u8; 3]] = &[
    [0x00, 0x05, 0x69],  // VMware
    [0x00, 0x0C, 0x29],  // VMware
    [0x00, 0x1C, 0x14],  // VMware
    [0x00, 0x50, 0x56],  // VMware
    [0x08, 0x00, 0x27],  // VirtualBox
    [0x00, 0x15, 0x5D],  // Hyper-V
    [0x00, 0x03, 0xFF],  // Microsoft Virtual PC
    [0x52, 0x54, 0x00],  // QEMU/KVM
];

/// Run all VM detection checks.
pub fn check() -> Result<(), AnalysisEnvironment> {
    // CPUID check
    if check_cpuid_hypervisor() {
        return Err(AnalysisEnvironment::VirtualMachine("CPUID hypervisor bit".into()));
    }

    // Registry check (Windows only)
    #[cfg(windows)]
    if let Some(vm_type) = check_registry_vm_keys() {
        return Err(AnalysisEnvironment::VirtualMachine(format!("Registry: {}", vm_type)));
    }

    // MAC check
    if let Some(vm_type) = check_mac_prefixes() {
        return Err(AnalysisEnvironment::VirtualMachine(format!("MAC: {}", vm_type)));
    }

    Ok(())
}

/// Check CPUID hypervisor present bit (bit 31 of ECX from CPUID.1).
fn check_cpuid_hypervisor() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        // CPUID with EAX=1 returns hypervisor bit in ECX[31]
        // We need to save/restore rbx as LLVM uses it internally
        let ecx: u32;
        unsafe {
            std::arch::asm!(
                "push rbx",
                "mov eax, 1",
                "cpuid",
                "pop rbx",
                out("ecx") ecx,
                out("eax") _,
                out("edx") _,
                options(nostack),
            );
        }
        return (ecx >> 31) & 1 == 1;
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

/// Check Windows registry for VM-specific keys.
#[cfg(windows)]
fn check_registry_vm_keys() -> Option<String> {
    use windows::Win32::System::Registry::*;
    use windows::core::PCWSTR;

    // Keys to check (produces Sysmon registry access events)
    let vm_keys = [
        (r"SOFTWARE\Oracle\VirtualBox Guest Additions", "VirtualBox"),
        (r"SOFTWARE\VMware, Inc.\VMware Tools", "VMware"),
        (r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters", "Hyper-V"),
        (r"SYSTEM\CurrentControlSet\Services\VBoxGuest", "VirtualBox"),
        (r"SYSTEM\CurrentControlSet\Services\VBoxMouse", "VirtualBox"),
        (r"SYSTEM\CurrentControlSet\Services\VBoxSF", "VirtualBox"),
        (r"SYSTEM\CurrentControlSet\Services\VBoxVideo", "VirtualBox"),
        (r"SYSTEM\CurrentControlSet\Services\vmci", "VMware"),
        (r"SYSTEM\CurrentControlSet\Services\vmhgfs", "VMware"),
        (r"SYSTEM\CurrentControlSet\Services\vmmouse", "VMware"),
    ];

    for (key_path, vm_type) in vm_keys {
        let wide_path: Vec<u16> = key_path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey = HKEY::default();

        let result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(wide_path.as_ptr()),
                0,
                KEY_READ,
                &mut hkey,
            )
        };

        if result.is_ok() {
            unsafe { RegCloseKey(hkey) };
            return Some(vm_type.to_string());
        }
    }

    None
}

/// Check MAC addresses for known VM OUI prefixes.
fn check_mac_prefixes() -> Option<String> {
    #[cfg(windows)]
    {
        check_mac_prefixes_windows()
    }
    #[cfg(unix)]
    {
        check_mac_prefixes_unix()
    }
}

#[cfg(windows)]
fn check_mac_prefixes_windows() -> Option<String> {
    use windows::Win32::NetworkManagement::IpHelper::*;
    use std::mem::size_of;

    unsafe {
        let mut buf_len: u32 = 0;
        let _ = GetAdaptersInfo(None, &mut buf_len);

        if buf_len == 0 {
            return None;
        }

        let mut buffer = vec![0u8; buf_len as usize];
        let adapter_info = buffer.as_mut_ptr() as *mut IP_ADAPTER_INFO;

        if GetAdaptersInfo(Some(adapter_info), &mut buf_len).is_err() {
            return None;
        }

        let mut current = adapter_info;
        while !current.is_null() {
            let info = &*current;
            if info.AddressLength >= 3 {
                let mac_prefix: [u8; 3] = [
                    info.Address[0],
                    info.Address[1],
                    info.Address[2],
                ];

                for (vm_prefix, vm_type) in [
                    (&[0x00, 0x05, 0x69], "VMware"),
                    (&[0x00, 0x0C, 0x29], "VMware"),
                    (&[0x00, 0x1C, 0x14], "VMware"),
                    (&[0x00, 0x50, 0x56], "VMware"),
                    (&[0x08, 0x00, 0x27], "VirtualBox"),
                    (&[0x00, 0x15, 0x5D], "Hyper-V"),
                    (&[0x52, 0x54, 0x00], "QEMU"),
                ] {
                    if mac_prefix == *vm_prefix {
                        return Some(vm_type.to_string());
                    }
                }
            }
            current = info.Next;
        }
    }

    None
}

#[cfg(unix)]
fn check_mac_prefixes_unix() -> Option<String> {
    use std::fs;

    // Read from /sys/class/net/*/address
    let net_dir = "/sys/class/net";
    if let Ok(entries) = fs::read_dir(net_dir) {
        for entry in entries.flatten() {
            let addr_path = entry.path().join("address");
            if let Ok(mac_str) = fs::read_to_string(&addr_path) {
                let mac_str = mac_str.trim();
                // Parse MAC like "00:0c:29:xx:xx:xx"
                let parts: Vec<&str> = mac_str.split(':').collect();
                if parts.len() >= 3 {
                    if let (Ok(a), Ok(b), Ok(c)) = (
                        u8::from_str_radix(parts[0], 16),
                        u8::from_str_radix(parts[1], 16),
                        u8::from_str_radix(parts[2], 16),
                    ) {
                        let mac_prefix = [a, b, c];
                        for vm_prefix in VM_MAC_PREFIXES {
                            if mac_prefix == *vm_prefix {
                                return Some(format!("{:02x}:{:02x}:{:02x}", a, b, c));
                            }
                        }
                    }
                }
            }
        }
    }

    None
}
