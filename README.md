# Oxide Loader

Multi-stage payload delivery chain for security research and education.

## Stages

| Stage | Language | Purpose | Size Target |
|-------|----------|---------|-------------|
| `stage1/` | C | Minimal native stub, XOR decrypt, fetch stage 2 | < 50KB |
| `stage2/` | Rust | Anti-analysis checks, fetch stage 3 | < 500KB |
| `stage3/` | Rust | Implant delivery and execution | < 1MB |

## Related

- [oxide](https://github.com/diemoeve/oxide) - The implant this loader delivers
- [oxide-stealer](https://github.com/diemoeve/oxide-stealer) - Credential extraction module
- [oxide-infra](https://github.com/diemoeve/oxide-infra) - Infrastructure deployment

## License

MIT
