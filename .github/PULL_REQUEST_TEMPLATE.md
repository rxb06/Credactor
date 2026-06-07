<!-- Branch from `develop` (the integration branch); `main` tracks releases. -->

**What & why**
Brief description of the change and the problem it solves (link any issue).

**Type**
- [ ] Bug fix
- [ ] New feature
- [ ] Detection/redaction pattern
- [ ] Docs / chore

**Checklist**
- [ ] `pytest` passes
- [ ] `ruff check credactor/ tests/` clean
- [ ] `mypy credactor/` clean
- [ ] `python -m credactor --ci .` exits 0 (no secrets in the diff)
- [ ] Tests added/updated for the change
- [ ] No real credentials in the diff, tests, or fixtures
