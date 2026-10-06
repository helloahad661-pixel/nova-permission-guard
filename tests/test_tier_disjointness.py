"""Tests: a capability must live in exactly one tier.

The permission engine resolves an action against AUTO -> GREEN -> YELLOW -> RED
and takes the FIRST tier that contains it. So an action listed in two tiers
silently resolves to the lower one, and YELLOW's "always require confirmation"
rule never fires.

Seven actions were listed in both green and yellow (write_file, open_url,
launch_app, close_app, create_folder, compress_files, set_volume). At GREEN --
which is what nova_voice_loop.py hardcodes -- every one of them was ALLOWED with
no confirmation, including writing files. That defeats the point of listing them
as YELLOW.

This test asserts the invariant for the whole manifest, so the next person who
adds a convenience duplicate gets told instead of shipping a silent bypass.

Run: /Users/noor/Nova/venv/bin/python3 tests/test_tier_disjointness.py
"""

import sys
import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from core.capability_engine import check_permission  # noqa: E402

# Highest privilege first, matching the engine's resolution order.
TIER_ORDER = ["red", "yellow", "green", "auto"]


def _manifest():
    return yaml.safe_load((REPO / "capabilities.yaml").read_text())


class TestTiersAreDisjoint(unittest.TestCase):
    def test_no_action_appears_in_two_tiers(self):
        manifest = _manifest()
        owner = {}
        clashes = []
        for tier in TIER_ORDER:
            for action in (manifest.get(tier) or {}).get("actions") or []:
                if action in owner and owner[action] != tier:
                    clashes.append(f"{action}: listed in both {owner[action]} and {tier}")
                else:
                    owner[action] = tier
        self.assertEqual(clashes, [], "action(s) in two tiers resolve to the "
                                     "lower one and skip confirmation:\n  "
                                     + "\n  ".join(clashes))

    def test_duplicate_within_one_tier_is_tolerated(self):
        """Same-tier repeats are harmless; only cross-tier repeats shift privilege.

        green.actions currently lists search_files and get_system_info twice.
        That resolves to the same tier either way, so it is noise, not a hole.
        """
        manifest = _manifest()
        green = (manifest.get("green") or {}).get("actions") or []
        for action in set(green):
            with self.subTest(action=action):
                self.assertLessEqual(
                    green.count(action), 2,
                    "expected at most a benign same-tier repeat, not a pile-up")


class TestPreviouslyLeakedActions(unittest.TestCase):
    """The seven that were duplicated must now actually require confirmation."""

    LEAKED = ["write_file", "open_url", "launch_app", "close_app",
              "create_folder", "compress_files", "set_volume"]

    def _probe(self, action):
        return check_permission({"action": action, "path": "~/Downloads",
                                 "app": "Safari", "command": "ls"}, "YELLOW")

    def test_denied_at_green(self):
        for action in self.LEAKED:
            with self.subTest(action=action):
                r = check_permission({"action": action, "path": "~/Downloads",
                                      "app": "Safari", "command": "ls"}, "GREEN")
                self.assertEqual(r.result.name, "DENIED",
                                 f"{action} is still reachable with no "
                                 f"confirmation at GREEN: {r.reason}")

    def test_requires_confirmation_at_yellow(self):
        for action in self.LEAKED:
            with self.subTest(action=action):
                # launch_app is on the absolute denylist, so it is DENIED at
                # every tier -- stricter than confirmation, which is fine.
                r = self._probe(action)
                self.assertIn(r.result.name, ("REQUIRES_CONFIRMATION", "DENIED"),
                              f"{action} at YELLOW is {r.result.name}, "
                              f"expected confirmation or denial")


class TestRedStaysRed(unittest.TestCase):
    """RED must never be reachable from a lower clearance, duplication or not."""

    def test_no_red_action_leaks_downwards(self):
        manifest = _manifest()
        red = set((manifest.get("red") or {}).get("actions") or [])
        for action in red:
            for clearance in ("AUTO", "GREEN", "YELLOW"):
                with self.subTest(action=action, clearance=clearance):
                    r = check_permission({"action": action, "path": "~/Downloads",
                                          "app": "Safari", "command": "ls"},
                                         clearance)
                    self.assertNotEqual(r.result.name, "ALLOWED",
                                        f"{action} is ALLOWED at {clearance}")


if __name__ == "__main__":
    unittest.main(verbosity=2)