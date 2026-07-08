# Contributing to HunterEngine

Thank you for considering a contribution to HunterEngine! This document explains how to get involved.

## ⚠️ Responsible Use

HunterEngine is a **defensive security tool** designed exclusively for **authorized bug bounty testing** and **penetration testing** with explicit written permission. Contributions that add offensive capabilities, exploit automation, or bypass authorization mechanisms will be rejected.

## Getting Started

1. **Fork** the repository.
2. **Clone** your fork:
   ```bash
   git clone https://github.com/<your-username>/hunterengine.git
   cd hunterengine
   ```
3. **Create a virtual environment**:
   ```bash
   python -m venv env
   source env/bin/activate   # Linux/macOS
   env\Scripts\activate      # Windows
   pip install -e ".[dev]"
   ```
4. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Workflow

### Branching Strategy

| Branch     | Purpose                                |
|------------|----------------------------------------|
| `main`     | Stable release branch                  |
| `develop`  | Integration branch for next release    |
| `feature/*`| New features                           |
| `fix/*`    | Bug fixes                              |
| `docs/*`   | Documentation updates                  |

### Code Style

- **Python 3.11+** required.
- Follow [PEP 8](https://peps.python.org/pep-0008/) with a **120 character line limit**.
- Use **type hints** on all function signatures.
- Write **docstrings** for all public classes and functions.
- Use `logging` instead of `print()`.

### Running Checks

```bash
# Lint
python -m flake8 . --max-line-length 120

# Type check
python -m mypy . --ignore-missing-imports

# Tests
python -m pytest tests/ -v
```

## Pull Request Process

1. Ensure your branch is up-to-date with `develop`.
2. Run all checks (lint, type check, tests).
3. Write a clear PR description explaining **what** and **why**.
4. Reference any related issues (`Fixes #123`).
5. Wait for at least one maintainer review.

## Adding a Detection Module

1. Create a new file in `detection/` (e.g., `detection/my_detector.py`).
2. Inherit from `BaseDetector` in `detection/base_detector.py`.
3. Implement the `name` property and `run()` method.
4. Add your module to the `detector_map` in `core/orchestrator.py`.
5. Add a toggle in `config/settings.yaml` under `detection.modules`.

## Reporting Bugs

Use the [Bug Report template](.github/ISSUE_TEMPLATE/bug_report.yml) and include:
- Steps to reproduce
- Expected vs. actual behavior
- HunterEngine version and Python version
- Relevant log output

## Questions?

Open a [Discussion](https://github.com/your-username/hunterengine/discussions) or reach out via issues.

---

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
