"""
Bug Bounty Playbooks

JSON playbooks for common bug bounty scenarios.
These provide structured, step-by-step workflows that can be
loaded programmatically or used as reference guides.

Available Playbooks:
    - cve-assessment-playbook.json: Full CVE assessment workflow
    - rapid-response-playbook.json: Emergency response to critical CVEs
    - bb-submission-playbook.json: From finding to submission

Usage:
    import json

    with open("playbooks/cve-assessment-playbook.json") as f:
        playbook = json.load(f)

    for phase in playbook["phases"]:
        print(f"Phase {phase['phase_id']}: {phase['name']}")
        for step in phase["steps"]:
            print(f"  - {step['description']}")
"""

import json
from pathlib import Path
from typing import Any


def load_playbook(name: str) -> dict[str, Any]:
    """
    Load a playbook by name.

    Args:
        name: Playbook name without extension
              (cve-assessment, rapid-response, bb-submission)

    Returns:
        Playbook dictionary

    Raises:
        FileNotFoundError: If playbook doesn't exist
        ValueError: If name is invalid
    """
    valid_names = ["cve-assessment", "rapid-response", "bb-submission"]

    if name not in valid_names:
        raise ValueError(
            f"Unknown playbook: {name}. Valid: {valid_names}"
        )

    playbook_dir = Path(__file__).parent
    filepath = playbook_dir / f"{name}-playbook.json"

    with open(filepath) as f:
        data: dict[str, Any] = json.load(f)
    return data


def list_playbooks() -> list[dict[str, str]]:
    """List all available playbooks with metadata."""
    playbook_dir = Path(__file__).parent
    playbooks = []

    for filepath in sorted(playbook_dir.glob("*playbook.json")):
        with open(filepath) as f:
            data = json.load(f)
            playbooks.append({
                "filename": filepath.name,
                "name": data.get("name", "Unknown"),
                "description": data.get("description", ""),
                "difficulty": data.get("difficulty", "unknown"),
                "estimated_time": data.get("estimated_time_hours", "unknown"),
            })

    return playbooks


def get_playbook_phases(playbook_name: str) -> list[dict[str, Any]]:
    """Get phases from a playbook."""
    playbook = load_playbook(playbook_name)
    phases: list[dict[str, Any]] = playbook.get("phases", [])
    return phases


def get_phase_steps(playbook_name: str, phase_id: str) -> list[dict[str, Any]]:
    """Get steps for a specific phase."""
    phases = get_playbook_phases(playbook_name)
    for phase in phases:
        if phase.get("phase_id") == phase_id:
            steps: list[dict[str, Any]] = phase.get("steps", [])
            return steps
    return []


def print_playbook_summary(playbook_name: str) -> None:
    """Print a human-readable summary of a playbook."""
    playbook = load_playbook(playbook_name)

    print(f"\n{'=' * 60}")
    print(f"PLAYBOOK: {playbook['name']}")
    print(f"{'=' * 60}")
    print(f"Description: {playbook['description']}")
    print(f"Difficulty: {playbook.get('difficulty', 'N/A')}")
    print(f"Estimated Time: {playbook.get('estimated_time_hours', 'N/A')} hours")
    print()

    for phase in playbook.get("phases", []):
        print(f"\nPhase {phase['phase_id']}: {phase['name']}")
        print(f"  {phase['description']}")
        print(f"  Estimated: {phase.get('estimated_time_minutes', 'N/A')} min")
        print()
        for step in phase.get("steps", []):
            badge = f"[{step.get('priority', 'P2')}]"
            print(f"    {badge} {step['step_id']}: {step['description']}")
