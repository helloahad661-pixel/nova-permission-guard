# nova-permission-guard

Tiered permission engine for AI assistants. Every action sits in a clearance
level — GREEN runs free, YELLOW asks first, RED always confirms — and an
absolute denylist overrides everything.

```bash
pip install pyyaml
python -m unittest discover -s tests -v
```

Edit the rules directly in `capabilities.yaml`. `test_tier_disjointness.py`
fails the build if any action ever appears in two tiers at once.

Maintained in Nova by `laya_agent` (decision engine). Extracted from the Nova
monorepo as a portfolio piece.
