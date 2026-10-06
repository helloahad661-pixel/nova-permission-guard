"""
Capability Engine: Formal permissions layer for Nova.

Loads capabilities.yaml and validates every intent against it before
execution. The denylist is absolute and overrides every clearance level.

Drop-in module — import and call check_permission() from the existing
gateway/security_agent without refactoring anything else.
"""

import os
import yaml
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

MANIFEST_PATH = Path.home() / "nova" / "capabilities.yaml"
BRAIN_FILE = Path.home() / "nova" / "memory" / "brain.json"


class PermissionResult(Enum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    REQUIRES_CONFIRMATION = "REQUIRES_CONFIRMATION"


@dataclass
class PermissionDecision:
    result: PermissionResult
    reason: str
    clearance_checked: str
    intent_summary: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class CapabilityEngine:
    """Validates intents against the capability manifest."""

    _instance = None  # Singleton so manifest is loaded once

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._loaded = False
        return cls._instance

    def __init__(self, manifest_path: Path = None):
        if self._loaded:
            return
        self.manifest_path = manifest_path or MANIFEST_PATH
        self.manifest = {}
        self.reload()
        self._loaded = True

    def reload(self):
        """Reload the manifest from disk. Call this after editing capabilities.yaml."""
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"Capability manifest not found at {self.manifest_path}")
        with open(self.manifest_path) as f:
            self.manifest = yaml.safe_load(f) or {}

    def _expand_path(self, path_str: str) -> str:
        return str(Path(os.path.expanduser(os.path.expandvars(path_str))).resolve())

    def _path_in_list(self, target_path: str, path_list: list) -> bool:
        """Check if target_path is inside (or equal to) any allowed/denied path."""
        if not target_path:
            return False
        try:
            target = Path(self._expand_path(target_path))
        except Exception:
            return False
        for allowed in path_list:
            try:
                allowed_resolved = Path(self._expand_path(allowed))
                if target == allowed_resolved or allowed_resolved in target.parents:
                    return True
            except Exception:
                continue
        return False

    def _log_decision(self, decision: PermissionDecision):
        """Log every permission decision to brain.json audit trail."""
        try:
            BRAIN_FILE.parent.mkdir(parents=True, exist_ok=True)
            if BRAIN_FILE.exists():
                import json
                with open(BRAIN_FILE) as f:
                    brain = json.load(f)
            else:
                brain = {"execution_log": [], "permission_log": []}

            if "permission_log" not in brain:
                brain["permission_log"] = []

            brain["permission_log"].append({
                "timestamp": decision.timestamp,
                "result": decision.result.value,
                "reason": decision.reason,
                "clearance": decision.clearance_checked,
                "intent": decision.intent_summary,
            })
            # Keep last 1000 entries
            brain["permission_log"] = brain["permission_log"][-1000:]

            import json
            with open(BRAIN_FILE, "w") as f:
                json.dump(brain, f, indent=2)
        except Exception as e:
            print(f"[CapabilityEngine] Warning: could not log decision: {e}")

    def check_permission(self, intent: dict, clearance: str) -> PermissionDecision:
        """
        Check whether an intent is permitted at the given clearance level.

        intent: dict with optional keys: action, path, app, hardware
        clearance: one of "GREEN", "YELLOW", "RED", "BLACK" (case-insensitive)

        Returns PermissionDecision with result: ALLOWED, DENIED, or REQUIRES_CONFIRMATION
        """
        clearance = clearance.upper()
        action = intent.get("action", "")
        path = intent.get("path")
        app = intent.get("app")
        hardware = intent.get("hardware")
        requires_confirmation_flag = intent.get("requires_user_confirmation", False)

        intent_summary = f"action={action}, path={path}, app={app}, hardware={hardware}"

        # ── STEP 1: Check absolute denylist first — overrides everything ──
        denied = self.manifest.get("denied", {})

        if action and action in denied.get("actions", []):
            decision = PermissionDecision(
                PermissionResult.DENIED,
                f"Action '{action}' is on the absolute denylist",
                clearance, intent_summary
            )
            self._log_decision(decision)
            return decision

        if app and app in denied.get("apps", []):
            decision = PermissionDecision(
                PermissionResult.DENIED,
                f"App '{app}' is on the absolute denylist",
                clearance, intent_summary
            )
            self._log_decision(decision)
            return decision

        if path and self._path_in_list(path, denied.get("paths", [])):
            decision = PermissionDecision(
                PermissionResult.DENIED,
                f"Path '{path}' is on the absolute denylist",
                clearance, intent_summary
            )
            self._log_decision(decision)
            return decision

        # ── STEP 2: BLACK clearance is disabled by default ──
        if clearance == "BLACK":
            black_config = self.manifest.get("black", {})
            is_populated = any(black_config.get(k) for k in ["paths", "apps", "hardware", "actions"])
            if not is_populated:
                decision = PermissionDecision(
                    PermissionResult.DENIED,
                    "BLACK clearance is disabled by default (manifest not populated)",
                    clearance, intent_summary
                )
                self._log_decision(decision)
                return decision

        # ── STEP 3: Determine which clearance tiers to check ──
        # Higher clearance includes all capabilities of lower tiers (GREEN ⊆ YELLOW ⊆ RED ⊆ BLACK)
        tier_order = ["AUTO", "GREEN", "YELLOW", "RED", "BLACK"]
        if clearance not in tier_order:
            decision = PermissionDecision(
                PermissionResult.DENIED,
                f"Unknown clearance level: {clearance}",
                clearance, intent_summary
            )
            self._log_decision(decision)
            return decision

        tiers_to_check = tier_order[:tier_order.index(clearance) + 1]

        found_at_tier = None
        for tier in tiers_to_check:
            tier_config = self.manifest.get(tier.lower(), {})

            action_ok = (not action) or (action in tier_config.get("actions", []))
            app_ok = (not app) or (app in tier_config.get("apps", []))
            path_ok = (not path) or self._path_in_list(path, tier_config.get("paths", []))
            hw_ok = (not hardware) or (hardware in tier_config.get("hardware", []))

            if action_ok and app_ok and path_ok and hw_ok:
                # Only count as a real match if at least one field was actually specified and matched
                if action or app or path or hardware:
                    found_at_tier = tier
                    break

        if found_at_tier is None:
            decision = PermissionDecision(
                PermissionResult.DENIED,
                f"Intent not found in any capability tier up to {clearance} (default deny)",
                clearance, intent_summary
            )
            self._log_decision(decision)
            return decision

        # ── STEP 4: Respect existing requires_user_confirmation flag from planner ──
        if requires_confirmation_flag:
            decision = PermissionDecision(
                PermissionResult.REQUIRES_CONFIRMATION,
                f"Planner flagged this intent as requiring confirmation",
                clearance, intent_summary
            )
            self._log_decision(decision)
            return decision

        # ── STEP 5: YELLOW/RED tiers always require confirmation by design ──
        # AUTO and GREEN are NO-confirmation tiers. AUTO is only safe because the function
        # itself locks privacy_status="private" in code, not just in the manifest.
        if found_at_tier in ["YELLOW", "RED"]:
            decision = PermissionDecision(
                PermissionResult.REQUIRES_CONFIRMATION,
                f"Matched at {found_at_tier} tier — confirmation required by policy",
                clearance, intent_summary
            )
            self._log_decision(decision)
            return decision

        # ── STEP 6: GREEN tier, no confirmation flag — fully allowed ──
        decision = PermissionDecision(
            PermissionResult.ALLOWED,
            f"Matched at {found_at_tier} tier — no confirmation required",
            clearance, intent_summary
        )
        self._log_decision(decision)
        return decision


# Module-level singleton accessor, so callers can just do:
#   from core.capability_engine import check_permission
_engine = None

def get_engine() -> CapabilityEngine:
    global _engine
    if _engine is None:
        _engine = CapabilityEngine()
    return _engine


def check_permission(intent: dict, clearance: str) -> PermissionDecision:
    """Convenience function — module-level entry point for the gateway to call."""
    return get_engine().check_permission(intent, clearance)


if __name__ == "__main__":
    # Quick self-test
    engine = CapabilityEngine()

    print("Test 1: GREEN scan_directory on ~/Downloads")
    result = engine.check_permission(
        {"action": "scan_directory", "path": "~/Downloads"}, "GREEN"
    )
    print(f"  → {result.result.value}: {result.reason}\n")

    print("Test 2: RED delete_files on ~/Downloads")
    result = engine.check_permission(
        {"action": "delete_files", "path": "~/Downloads"}, "RED"
    )
    print(f"  → {result.result.value}: {result.reason}\n")

    print("Test 3: Denied path /System")
    result = engine.check_permission(
        {"action": "scan_directory", "path": "/System"}, "RED"
    )
    print(f"  → {result.result.value}: {result.reason}\n")

    print("Test 4: Denied app Terminal")
    result = engine.check_permission(
        {"action": "launch_app", "app": "Terminal"}, "YELLOW"
    )
    print(f"  → {result.result.value}: {result.reason}\n")

    print("Test 5: BLACK clearance (should be disabled by default)")
    result = engine.check_permission(
        {"action": "anything"}, "BLACK"
    )
    print(f"  → {result.result.value}: {result.reason}\n")

    print("Test 6: Unknown action at GREEN (default deny)")
    result = engine.check_permission(
        {"action": "launch_nuclear_missiles", "path": "~/Downloads"}, "GREEN"
    )
    print(f"  → {result.result.value}: {result.reason}\n")

