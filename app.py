import os
import sys
import json
import re
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory
import anthropic

app = Flask(__name__, static_folder="static")

# Verify API key on startup
api_key = os.environ.get("ANTHROPIC_API_KEY")
if not api_key:
    print("ERROR: ANTHROPIC_API_KEY environment variable is not set.", file=sys.stderr)
    print("Set it with: export ANTHROPIC_API_KEY=your_key_here", file=sys.stderr)
    sys.exit(1)

client = anthropic.Anthropic(api_key=api_key)
MODEL = "claude-sonnet-4-20250514"

PROMPTS_DIR = Path(__file__).parent / "prompts"


def load_prompt(name: str) -> str:
    path = PROMPTS_DIR / f"{name}.txt"
    if path.exists():
        return path.read_text()
    raise FileNotFoundError(f"Prompt file not found: {path}")


def extract_json_block(text: str) -> dict:
    """Extract JSON from a markdown code block or raw JSON response."""
    # Try ```json ... ``` block first
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        return json.loads(match.group(1))
    # Try finding the first { ... } in the text
    match = re.search(r"(\{.*\})", text, re.DOTALL)
    if match:
        return json.loads(match.group(1))
    raise ValueError("No JSON object found in response")


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze_findings():
    """Tab 1: Analyze STIG findings from XML or free text."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    findings_input = (data.get("findings_text") or "").strip()
    base_image = (data.get("base_image") or "").strip()
    container_purpose = (data.get("container_purpose") or "").strip()

    if not findings_input:
        return jsonify({"error": "findings_text is required"}), 400

    try:
        system_prompt = load_prompt("stig_analyze")
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 500

    user_message = f"""Analyze the following STIG findings for a Docker container.

Base Image: {base_image or 'Not specified'}
Container Purpose: {container_purpose or 'Not specified'}

Findings:
{findings_input}

Return a JSON object with this exact structure:
{{
  "summary": {{
    "overall_risk": "HIGH|MEDIUM|LOW",
    "cat1_count": 0,
    "cat2_count": 0,
    "cat3_count": 0,
    "narrative": "2-3 sentence plain English risk posture summary"
  }},
  "findings": [
    {{
      "check_id": "V-XXXXXX or unknown",
      "severity": "CAT I|CAT II|CAT III",
      "title": "Short title",
      "plain_english": "What this finding means in plain language",
      "remediation": "Step-by-step remediation guidance",
      "dockerfile_fix": "RUN ... or null if not applicable",
      "requires_human_judgment": false,
      "human_judgment_note": null
    }}
  ],
  "hardened_dockerfile": "# Complete Dockerfile with all applicable fixes\\nFROM {base_image or 'your-base-image'}\\n..."
}}

IMPORTANT: Return only the JSON object, no markdown, no explanation."""

    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        raw = response.content[0].text
        result = extract_json_block(raw)
        return jsonify(result)
    except json.JSONDecodeError as e:
        return jsonify({"error": f"AI returned invalid JSON: {e}", "raw": raw}), 500
    except anthropic.APIError as e:
        return jsonify({"error": f"Anthropic API error: {e}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/harden", methods=["POST"])
def harden_dockerfile():
    """Tab 2: Harden an existing Dockerfile against a target STIG/SRG."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    dockerfile = (data.get("dockerfile") or "").strip()
    stig_target = (data.get("stig_target") or "DISA Container Platform SRG").strip()

    if not dockerfile:
        return jsonify({"error": "dockerfile is required"}), 400

    system_prompt = """You are a Docker security hardening expert with deep knowledge of DISA STIGs,
CIS Docker Benchmark, and container security best practices. You produce hardened Dockerfiles
with inline comments explaining each security change."""

    user_message = f"""Harden the following Dockerfile against: {stig_target}

Original Dockerfile:
```
{dockerfile}
```

Rules:
1. Make minimal, surgical changes — do not rewrite unnecessarily
2. Add inline comments before each hardening change explaining the STIG/CIS control
3. Use RUN, USER, and COPY best practices
4. Preserve the original functionality

Return a JSON object with this exact structure:
{{
  "hardened_dockerfile": "# Complete hardened Dockerfile content here",
  "changes": [
    {{
      "line_reference": "approx line or instruction",
      "change_type": "ADDED|MODIFIED|REMOVED",
      "description": "What was changed and why",
      "stig_reference": "V-XXXXXX or CIS X.X or descriptive reference"
    }}
  ],
  "warnings": ["any warnings about findings requiring manual review"]
}}

IMPORTANT: Return only the JSON object, no markdown wrapper."""

    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        raw = response.content[0].text
        result = extract_json_block(raw)
        return jsonify(result)
    except json.JSONDecodeError as e:
        return jsonify({"error": f"AI returned invalid JSON: {e}", "raw": raw}), 500
    except anthropic.APIError as e:
        return jsonify({"error": f"Anthropic API error: {e}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/poam", methods=["POST"])
def generate_poam():
    """Tab 3: Generate POA&M language from findings."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    findings_input = (data.get("findings_text") or "").strip()
    system_name = (data.get("system_name") or "System Name TBD").strip()
    responsible_party = (data.get("responsible_party") or "TBD").strip()

    if not findings_input:
        return jsonify({"error": "findings_text is required"}), 400

    system_prompt = """You are a DoD cybersecurity compliance expert specializing in
Plan of Action & Milestones (POA&M) documentation for RMF packages. You produce
clear, professional POA&M entries that meet DISA and NIST SP 800-37 requirements."""

    user_message = f"""Generate POA&M entries for the following STIG findings.

System Name: {system_name}
Responsible Party: {responsible_party}

Findings:
{findings_input}

Return a JSON object with this structure:
{{
  "poam_entries": [
    {{
      "poam_id": "POAM-001",
      "check_id": "V-XXXXXX or derived",
      "weakness_name": "Short weakness title",
      "weakness_description": "Clear description of the vulnerability and its impact",
      "severity": "CAT I|CAT II|CAT III",
      "resources_required": "Description of resources needed for remediation",
      "scheduled_completion_date": "LEAVE_BLANK",
      "milestones": [
        {{
          "milestone_number": 1,
          "milestone_description": "Specific actionable milestone",
          "completion_date": "LEAVE_BLANK"
        }}
      ],
      "responsible_party": "{responsible_party}",
      "status": "Ongoing",
      "comments": "Any relevant notes or caveats"
    }}
  ],
  "plain_text_export": "Complete POA&M formatted as plain text for copy-paste"
}}

IMPORTANT: Return only the JSON object. Leave all date fields as the literal string LEAVE_BLANK."""

    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        raw = response.content[0].text
        result = extract_json_block(raw)
        return jsonify(result)
    except json.JSONDecodeError as e:
        return jsonify({"error": f"AI returned invalid JSON: {e}", "raw": raw}), 500
    except anthropic.APIError as e:
        return jsonify({"error": f"Anthropic API error: {e}"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/sample", methods=["GET"])
def get_sample():
    """Return the sample findings XML for testing."""
    sample_path = Path(__file__).parent / "sample_data" / "sample_findings.xml"
    if not sample_path.exists():
        return jsonify({"error": "Sample file not found"}), 404
    return jsonify({"xml": sample_path.read_text()})


if __name__ == "__main__":
    print(f"STIG Assist starting on http://localhost:5000")
    print(f"Model: {MODEL}")
    app.run(debug=True, host="0.0.0.0", port=5000)
