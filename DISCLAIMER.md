# Disclaimer

This project is built for educational purposes: understanding how offensive tools work to build better defenses. It is designed for use in isolated lab environments only.

Posture:
- Default C2 address is localhost (127.0.0.1)
- Obfuscation and anti-analysis techniques (compile-time string XOR, PEB walk + djb2 API resolution, Hell's Hall indirect syscalls, decoy IAT shaping, QPC/Sleep + CPU-loop anti-emulation, polymorphic build) are present in the stage1 loader. Each is documented in `stage1/README.md` and ships with paired YARA + Sigma detection rules under `detection/`.
- Detection rules ship alongside every technique
- No precompiled binaries in the repository. Source-only distribution.
- AGPL-licensed. Lab CA self-signing; production deployment requires user-provided commercial cert.

Usage outside isolated lab environments is your responsibility. The author does not condone unauthorized access to computer systems.

For legal posture see [oxide/LEGAL_REVIEW.md](https://github.com/diemoeve/oxide/blob/main/LEGAL_REVIEW.md). Self-assessment, not legal advice.
