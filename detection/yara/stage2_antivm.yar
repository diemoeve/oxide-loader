/*
 * Oxide Loader Stage 2 - Anti-VM Detection
 *
 * Detects VM detection strings and patterns in Stage 2 binary.
 *
 * Coverage: Static detection of anti-VM code
 * False positive risk: Low - specific VM artifact strings are distinctive
 */

rule Oxide_Stage2_VM_Registry_Strings
{
    meta:
        description = "Detects Oxide Stage 2 by VM registry check strings"
        author = "diemoeve"
        date = "2026-04-10"
        reference = "oxide-loader/stage2/src/anti_analysis/vm_detect.rs"
        mitre_attack = "T1497.001"  // System Checks
        severity = "high"

    strings:
        // VirtualBox registry paths
        $vbox1 = "VirtualBox Guest Additions" ascii wide nocase
        $vbox2 = "VBoxGuest" ascii wide nocase
        $vbox3 = "VBoxMouse" ascii wide nocase
        $vbox4 = "VBoxSF" ascii wide nocase
        $vbox5 = "VBoxVideo" ascii wide nocase

        // VMware registry paths
        $vmware1 = "VMware Tools" ascii wide nocase
        $vmware2 = "vmci" ascii wide nocase
        $vmware3 = "vmhgfs" ascii wide nocase
        $vmware4 = "vmmouse" ascii wide nocase

        // Hyper-V
        $hyperv = "Virtual Machine\\Guest\\Parameters" ascii wide nocase

    condition:
        3 of them
}

rule Oxide_Stage2_VM_MAC_Prefixes
{
    meta:
        description = "Detects Oxide Stage 2 by VM MAC OUI prefix bytes"
        author = "diemoeve"
        date = "2026-04-10"
        reference = "oxide-loader/stage2/src/anti_analysis/vm_detect.rs"
        mitre_attack = "T1497.001"
        severity = "medium"

    strings:
        // VMware MAC prefixes
        $mac_vmware1 = { 00 05 69 }
        $mac_vmware2 = { 00 0C 29 }
        $mac_vmware3 = { 00 1C 14 }
        $mac_vmware4 = { 00 50 56 }

        // VirtualBox MAC prefix
        $mac_vbox = { 08 00 27 }

        // Hyper-V MAC prefix
        $mac_hyperv = { 00 15 5D }

        // QEMU MAC prefix
        $mac_qemu = { 52 54 00 }

    condition:
        3 of them
}

rule Oxide_Stage2_CPUID_Check
{
    meta:
        description = "Detects CPUID hypervisor bit check pattern"
        author = "diemoeve"
        date = "2026-04-10"
        reference = "oxide-loader/stage2/src/anti_analysis/vm_detect.rs"
        mitre_attack = "T1497.001"
        severity = "medium"

    strings:
        // CPUID instruction followed by ECX bit check
        // push rbx; mov eax, 1; cpuid; pop rbx; ... shr ecx, 31
        $cpuid_pattern = {
            53              // push rbx
            B8 01 00 00 00  // mov eax, 1
            0F A2           // cpuid
            5B              // pop rbx
        }

        // Alternative: just CPUID with hypervisor leaf
        $cpuid_leaf = {
            B8 01 00 00 00  // mov eax, 1
            0F A2           // cpuid
            [0-20]
            C1 E9 1F        // shr ecx, 31 (extract bit 31)
        }

    condition:
        any of them
}
