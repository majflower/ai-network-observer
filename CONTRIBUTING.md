# Contributing to AI Network Observer

Thank you for your interest in contributing! This document provides guidelines and instructions.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help create a welcoming environment

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported
2. Use the bug report template
3. Include:
   - Python version
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior
   - Error messages and logs

### Suggesting Features

1. Check existing feature requests
2. Describe the use case
3. Explain expected behavior
4. Consider implementation implications

### Pull Requests

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow code style guidelines
   - Add tests for new functionality
   - Update documentation

4. **Run tests**
   ```bash
   make test
   make lint
   ```

5. **Commit your changes**
   ```bash
   git commit -m "Add feature: description"
   ```
   Use conventional commits:
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation
   - `test:` Tests
   - `refactor:` Code refactoring
   - `perf:` Performance improvement

6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a Pull Request**

## Development Setup

### Prerequisites

```bash
# Install system dependencies
sudo apt-get install libpcap-dev tcpdump

# Optional: eBPF support
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)
```

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/ai-network-observer.git
cd ai-network-observer

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
make install-dev

# Setup pre-commit hooks
pre-commit install
```

## Code Style

### Python

- **PEP 8** compliant
- **Line length**: 100 characters
- **Formatter**: Black
- **Linter**: Flake8
- **Type hints**: Encouraged but not required

```bash
# Format code
make format

# Lint code
make lint
```

### Documentation

- **Docstrings**: Google style
- **Type hints**: Include where possible
- **Comments**: Explain why, not what

Example:
```python
def analyze_dns(packet: Packet) -> Optional[Dict[str, Any]]:
    """
    Analyze DNS packet for anomalies.
    
    Args:
        packet: Scapy packet object containing DNS layer
    
    Returns:
        Dictionary with analysis results, or None if not DNS
    
    Raises:
        ValueError: If packet is malformed
    """
    pass
```

## Testing

### Writing Tests

- Place tests in `tests/` directory
- Match source file structure
- Use pytest fixtures
- Aim for >80% coverage

```python
import pytest

def test_dns_analysis():
    """Test DNS analysis functionality"""
    analyzer = DNSAnalyzer()
    result = analyzer.analyze("google.com")
    assert result['risk_score'] < 50
```

### Running Tests

```bash
# All tests
make test

# Fast tests only
make test-fast

# Specific file
pytest tests/test_dns_analyzer.py -v

# With coverage
pytest --cov=src --cov-report=html
```

## Adding New Features

### New Protocol Extractor

1. Create file in `src/extractors/`
2. Implement base interface
3. Add tests in `tests/`
4. Update documentation

Example structure:
```python
class NewProtocolExtractor:
    def extract(self, packet):
        """Extract features from packet"""
        pass
    
    def analyze(self, features):
        """Analyze extracted features"""
        pass
```

### New Anomaly Detection

1. Implement in appropriate module
2. Add configuration parameters
3. Include tests with known anomalies
4. Document detection logic

## Documentation

### Updating README

- Keep examples up-to-date
- Add new features to feature list
- Update installation instructions

### API Documentation

```bash
# Generate API docs
cd docs
make html
```

## Release Process

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Create git tag
4. Build and publish

```bash
# Build
python -m build

# Publish to PyPI (maintainers only)
twine upload dist/*
```

## Security

### Reporting Vulnerabilities

- **DO NOT** create public issues for security vulnerabilities
- Email: security@example.com
- Include:
  - Description of vulnerability
  - Steps to reproduce
  - Potential impact
  - Suggested fix (if any)

### Security Guidelines

- Never commit secrets or API keys
- Validate all user input
- Use parameterized queries
- Follow principle of least privilege
- Keep dependencies updated

## Questions?

- Open a GitHub Discussion
- Join our Discord (link)
- Email: dev@example.com

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
