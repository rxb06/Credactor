# Contributing

Thanks for your interest in Credactor. Bug reports, feature requests, and pull requests are welcome via [GitHub Issues](https://github.com/rxb06/Credactor/issues).

## Development Setup

```bash
git clone https://github.com/rxb06/Credactor.git
cd Credactor
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest
ruff check src/ tests/
```

## Code Style

- Formatted with [Ruff](https://docs.astral.sh/ruff/)
- Type hints on all public functions
- No external runtime dependencies — stdlib only

## Development Process

AI tools were used during development for code review, bug detection, security auditing, and documentation structuring. All output was reviewed and validated manually. The architecture, design decisions, and feature selection are the maintainer's own.
