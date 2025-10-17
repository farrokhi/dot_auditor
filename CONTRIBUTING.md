# Contributing to DoT Auditor

## Development Setup

```bash
# Clone the repository
git clone https://github.com/farrokhi/dot_auditor.git
cd dot_auditor

# Install dependencies
pip install -r requirements.txt
```

## Running Tests

```bash
# Run all tests
python3 -m pytest test_dot_auditor.py -v

# Run with coverage
python3 -m pytest test_dot_auditor.py --cov=dot_auditor --cov-report=term-missing
```

## Code Quality

```bash
# Type checking
python3 -m mypy dot_auditor.py

# Linting
python3 -m pylint dot_auditor.py
```

## Quality Standards

- **Type Safety**: 100% type coverage with mypy
- **Testing**: Comprehensive test suite with pytest
- **Code Quality**: Pylint score ≥ 9.5
- **CI/CD**: All checks must pass before merge

## Submitting Changes

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Ensure all tests pass
5. Submit a pull request

## CI/CD Pipeline

GitHub Actions automatically runs on every push:
- Type checking with mypy
- Code quality with pylint
- Tests with pytest
- Coverage reporting to Codecov

Tests run against Python 3.10, 3.11, and 3.12.
