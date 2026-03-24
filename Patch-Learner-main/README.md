# 🔍 Patch-Learner

> **LLM Agent-based Variant-Driven 0-Day Discovery Framework for IoT Surveillance Firmware**

---


### Core Idea

```
Known CVE Patch → LLM Pattern Extraction → Pattern Generalization → Cross-Device Variant Hunting
```

### Pipeline: Extract → Diff → Analyze → Store

| Stage | Input | Output |
|-------|-------|--------|
| **Extract** (Step 0~4) | Patched + Unpatched firmware pair | Decompiled pseudocode + BinDiff |
| **Diff** (Step 5~7) | BinDiff matched functions | Pseudocode diff per function |
| **Score** (Step 8) | 5,497 changed functions | 1,099 security candidates (IoT prioritized) |
| **Analyze** (Step 9) | Security candidates + diff | 34 Vulnerability Pattern Cards |
| **Validate & Store** (Step 10) | Pattern Cards JSON | Pydantic-validated SQLite DB |

---


| Vendor | Model | Architecture | Prize |
|--------|-------|-------------|-------|
| **Ubiquiti** | AI Pro (UniFi Protect) | ARM64 | $30,000 |
| **Synology** | CC400W Camera | ARM64 | $30,000 |

## Tools & Stack

- **IDA Pro 9.0** + BinExport plugin (decompile + export)
- **BinDiff** (binary-level function matching)
- **Binwalk** (firmware extraction)
- **Python 3.11+** + Pydantic (automation, validation)
- **Claude Code** (LLM multi-agent orchestration — Opus supervisor + Sonnet analysts)
- **SQLite** (pattern card DB storage)

## Project Structure

```
Patch-Learner/
├── README.md
├── PROJECT_WHITEPAPER.md      # Project context & AI session guide
├── docs/                      # Research reports & analysis
├── src/
│   ├── extractors/            # Firmware extraction automation
│   ├── analyzers/
│   │   ├── bindiff_pipeline.py          # Step 0~7 main pipeline
│   │   ├── generate_security_candidates.py  # Step 8: IoT scoring
│   │   ├── multi_agent_pipeline.py      # Step 9: Discovery→Analysis
│   │   └── pattern_card_schema.py       # Step 10: Pydantic validation
│   ├── db/
│   │   ├── schema.sql                   # SQLite schema (8 tables)
│   │   ├── init_db.py                   # DB initialization
│   │   ├── load_pattern_cards.py        # JSON → DB loader
│   │   └── patch_learner.db             # SQLite DB (34 pattern cards)
│   └── hunters/               # Variant hunting engine
├── firmware/                  # (gitignored) Downloaded firmware files
├── results/                   # Analysis results & findings
└── poc/                       # Proof-of-concept exploits
```

## Getting Started

See [PROJECT_WHITEPAPER.md](PROJECT_WHITEPAPER.md) for full project context, tool setup, and development guide.

## Team

- 2-person team
- Role A (Hunter): Manual reversing + PoC development
- Role B (Builder): AI framework + IDA MCP automation

## License

This project is for academic research and responsible security disclosure only.
