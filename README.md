## Project Overview

Build a **human-AI collaborative threat hunting framework** using Jupyter Notebooks as the operational workspace. An LLM agent retrieves security logs, performs autonomous statistical analysis, generates visualizations, and produces STIX-formatted intelligence — while you supervise, validate, and steer the investigation in real-time.

**This project proves you can:**

- Supervise AI agents performing security analysis (2026 Tier 4 skill)
- Apply prompt engineering to real security workflows
- Combine data science (pandas, matplotlib) with SOC operations
- Generate machine-readable threat intelligence (STIX 2.1)
- Operate as the strategic "human-in-the-loop" — the core 2026 SOC role

**The Impact:** Reduce hunt cycle time from 8 hours (manual) to 45 minutes (AI-assisted) while increasing detection coverage by 30%.

## Tools & Technologies

| **Tool** | **Role** | **Function** |
|---|---|---|
| **Jupyter Notebook** | Analysis workspace | Interactive Python environment for collaborative hunting |
| **Local LLM** | AI analyst agent | Autonomous log analysis, pattern recognition, hypothesis generation |
| **Python (pandas, numpy)** | Data processing | Log parsing, statistical analysis, correlation |
| **Matplotlib / Seaborn** | Visualization | Charts, heatmaps, timelines for hunt findings |
| **Splunk SDK / Elastic API** | Data source | Pull security logs into Jupyter for analysis |
| **python-stix2** | Intelligence output | Format findings as STIX 2.1 bundles |
| **Sigma CLI** | Detection output | Convert hunt findings to Sigma detection rules |

### Infrastructure Requirements

- Python 3.10+ with Jupyter Lab
- Local LLM running on the host system
- Splunk Free (local) or Elastic Stack with sample datasets
- MITRE ATT&CK STIX data (public GitHub repo)
- 8 GB RAM minimum, any OS
