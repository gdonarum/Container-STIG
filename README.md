# STIG Assist

A web application for applying DISA STIGs to Docker containers at scale.

## Quick Start

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
python app.py
```

Open http://localhost:5000 in your browser.

## Features

**Tab 1 — Findings Analyzer**
Paste Nessus/SCAP XML or plain-text findings. Get AI-analyzed results grouped by severity (CAT I/II/III) with plain-English explanations, remediation steps, Dockerfile fixes, and a generated hardened Dockerfile.

**Tab 2 — Dockerfile Hardener**
Paste an existing Dockerfile and select a target STIG/SRG. Get a hardened version with inline comments and a side-by-side diff.

**Tab 3 — POA&M Helper**
Paste findings and get draft Plan of Action & Milestones entries with milestone language ready for human completion dates.

## Testing

```bash
python -m pytest tests/ -v
# or
python -m unittest discover tests/
```

## Requirements

- Python 3.9+
- `ANTHROPIC_API_KEY` environment variable (Claude claude-sonnet-4-20250514)
- No other external services required

## Sample Data

Load the sample Nessus XML via the "Load Sample" button in the Findings Analyzer tab, or find it at `sample_data/sample_findings.xml`.

## Configuration

The system prompt for STIG analysis is in `prompts/stig_analyze.txt` — edit this file to tune AI behavior without touching Python code.
