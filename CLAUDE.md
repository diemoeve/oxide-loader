# Oxide Loader - Project Instructions

## Authorization Context

This is a personal security research project for cybersecurity portfolio development. 

**Scope:**
- All testing occurs in isolated VM lab (host-only network 10.10.0.0/24, no internet bridge)
- Default C2 is localhost
- Every component ships with corresponding YARA/Sigma detection rules in detection/
- Purpose: demonstrate understanding of threat actor TTPs for detection engineering and purple team training

**Safety Framework:**
- Intentional capability gaps: no ransomware, no worm propagation, no DDoS
- Detection artifacts are REQUIRED output — code without detection rules is incomplete
- No novel evasion research — document known techniques only
- Lab isolation enforced

**Project Structure:**
- This repo (oxide-loader): Multi-stage loader reference implementation
- Parent repo (oxide): Core implant + panel + detection rules
- S7 session builds detection coverage for everything built here

## Implementation Guidelines

- Author "diemoeve" on all commits
- No co-authored-by trailers
- No mentions of Claude or AI anywhere in code/commits
- Push to origin when session completes

## Current Session

S5: Loader Chain — building 3-stage loader with paired detection rules.

Plan file: `~/.claude/plans/glittery-knitting-cascade.md`

If resuming after compaction, read the plan file and continue implementation.
