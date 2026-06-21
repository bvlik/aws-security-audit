# Contributing

Thanks for your interest! Checks are read-only by design.

## Dev setup
```bash
pip install -r requirements.txt
pip install pytest ruff bandit
```

## Before opening a PR
- `ruff check .` — lint
- `bandit -r src` — security scan
- `python -m compileall src` — syntax
- `pytest -q` — tests

## Adding a check
Drop a file in `checks/`, subclass `Check`, add it to the registry. Keep it read-only
(`list`/`get`/`describe`), and prefer extracting pure helpers so they can be unit-tested.

## Conventions
- Conventional commit messages (`feat:`, `fix:`, `docs:`, `test:`)
