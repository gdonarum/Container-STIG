#!/usr/bin/env python3
# Copyright (c) 2026 Gregory Donarum. All rights reserved.
# Licensed under the PolyForm Noncommercial License 1.0.0 — see LICENSE file.

"""
Hardening script for generating STIG-compliant Dockerfiles.

Usage:
    python harden.py --base-image ubuntu:22.04 --stig-target "Ubuntu 22.04 STIG" --output-dir ./output
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

import anthropic

MODEL = "claude-sonnet-4-20250514"

DOCKERFILE_HARDEN_PROMPT = """You are a Docker security hardening expert with deep knowledge of DISA STIGs,
CIS Docker Benchmark, and container security best practices. You produce hardened Dockerfiles
with inline comments explaining each security change."""


def extract_json_block(text: str) -> dict:
    """Extract JSON from a markdown code block or raw JSON response."""
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        return json.loads(match.group(1))
    match = re.search(r"(\{.*\})", text, re.DOTALL)
    if match:
        return json.loads(match.group(1))
    raise ValueError("No JSON object found in response")


def generate_base_dockerfile(base_image: str) -> str:
    """Generate a minimal Dockerfile for the base image."""
    return f"""FROM {base_image}

# Minimal base image for hardening
LABEL maintainer="STIG Assist Pipeline"
LABEL description="Base image to be hardened"

# Default shell
SHELL ["/bin/sh", "-c"]

# Default command
CMD ["/bin/sh"]
"""


def harden_dockerfile(client: anthropic.Anthropic, dockerfile: str, stig_target: str) -> dict:
    """Call Claude API to harden the Dockerfile."""
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
5. Create a non-root user and switch to it
6. Remove unnecessary packages and clean caches
7. Set appropriate file permissions

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

    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=DOCKERFILE_HARDEN_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    raw = response.content[0].text
    return extract_json_block(raw)


def main():
    parser = argparse.ArgumentParser(description="Generate hardened Dockerfiles")
    parser.add_argument("--base-image", required=True, help="Base image to harden (e.g., ubuntu:22.04)")
    parser.add_argument("--stig-target", required=True, help="STIG/CIS target (e.g., 'Ubuntu 22.04 STIG')")
    parser.add_argument("--output-dir", required=True, help="Output directory for hardened Dockerfile")
    parser.add_argument("--output-json", help="Optional: output JSON file for changes metadata")
    args = parser.parse_args()

    # Check for API key
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)

    # Generate base Dockerfile
    print(f"Generating base Dockerfile for {args.base_image}...")
    base_dockerfile = generate_base_dockerfile(args.base_image)

    # Harden the Dockerfile
    print(f"Hardening against {args.stig_target}...")
    try:
        result = harden_dockerfile(client, base_dockerfile, args.stig_target)
    except Exception as e:
        print(f"ERROR: Failed to harden Dockerfile: {e}", file=sys.stderr)
        sys.exit(1)

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Write hardened Dockerfile
    dockerfile_path = output_dir / "Dockerfile"
    dockerfile_path.write_text(result["hardened_dockerfile"])
    print(f"Hardened Dockerfile written to: {dockerfile_path}")

    # Write changes metadata
    if args.output_json:
        json_path = Path(args.output_json)
        json_path.write_text(json.dumps(result, indent=2))
        print(f"Changes metadata written to: {json_path}")

    # Print summary
    print(f"\nChanges made: {len(result.get('changes', []))}")
    for change in result.get("changes", []):
        print(f"  - [{change['change_type']}] {change['description']}")

    if result.get("warnings"):
        print(f"\nWarnings ({len(result['warnings'])}):")
        for warning in result["warnings"]:
            print(f"  ⚠ {warning}")

    print("\nDone!")


if __name__ == "__main__":
    main()
