# Contributing to Smart Contract Analyzer

Thank you for your interest in contributing to Smart Contract Analyzer! This document provides guidelines and information for contributors.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)
- [Bug Reports](#bug-reports)
- [Feature Requests](#feature-requests)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Community Guidelines](#community-guidelines)

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Basic knowledge of Python and smart contracts

### Setting Up Your Development Environment

1. **Fork the repository**
   ```bash
   # Fork the repository on GitHub first, then clone your fork
   git clone https://github.com/YOUR_USERNAME/SmartContractAnalizer.git
   cd SmartContractAnalizer
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements_enhanced.txt
   pip install -r requirements-dev.txt  # Development dependencies
   ```

4. **Run the application**
   ```bash
   python smart_contract_analyzer_dark.py
   ```

## Development Setup

### Project Structure

```
SmartContractAnalizer/
|
|--- smart_contract_analyzer_dark.py  # Main GUI application
|--- analyzer.py                      # Core analysis engine
|--- ml_detector.py                   # Machine learning module
|--- behavioral_analyzer.py           # Behavioral analysis
|--- blockchain_integration.py        # Blockchain data integration
|--- reporting_system.py              # Report generation
|--- batch_analyzer.py                # Batch processing
|--- bytecode_analyzer.py             # Bytecode analysis
|--- plugin_system.py                 # Plugin architecture
|--- cve_database.py                  # Vulnerability database
|
|--- tests/                           # Test suite
|--- docs/                            # Documentation
|--- examples/                        # Example contracts
|--- resources/                       # Additional resources
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_analyzer.py

# Run with coverage
pytest --cov=. tests/

# Run linting
flake8 *.py
black --check *.py
```

### Code Style

We use the following tools to maintain code quality:

- **Black** for code formatting
- **Flake8** for linting
- **mypy** for type checking
- **pytest** for testing

#### Formatting Code

```bash
# Format code with Black
black *.py

# Check formatting without making changes
black --check *.py
```

#### Linting

```bash
# Run flake8
flake8 *.py --max-line-length=100
```

#### Type Checking

```bash
# Run mypy
mypy *.py
```

## Submitting Changes

### Workflow

1. **Create a new branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write code following our style guidelines
   - Add tests for new functionality
   - Update documentation as needed

3. **Test your changes**
   ```bash
   # Run tests
   pytest tests/
   
   # Check formatting
   black --check *.py
   
   # Run linting
   flake8 *.py
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add new vulnerability detection pattern"
   ```

5. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request**
   - Go to your fork on GitHub
   - Click "New Pull Request"
   - Fill out the PR template
   - Wait for review

### Commit Message Format

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:
```
feat(analyzer): add reentrancy detection pattern
fix(gui): resolve dark mode color issue
docs(readme): update installation instructions
```

## Bug Reports

### Reporting Bugs

1. **Check existing issues** - Search for similar issues first
2. **Create a new issue** - Use the bug report template
3. **Provide detailed information**:
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details
   - Screenshots if applicable

### Bug Report Template

```markdown
**Bug Description**
Brief description of the bug

**Steps to Reproduce**
1. Go to...
2. Click on...
3. See error

**Expected Behavior**
What you expected to happen

**Actual Behavior**
What actually happened

**Environment**
- OS: [e.g., Windows 10, macOS 12.0]
- Python version: [e.g., 3.9.0]
- Application version: [e.g., 1.0.0]

**Additional Context**
Any other relevant information
```

## Feature Requests

### Requesting Features

1. **Check existing issues** - Look for similar requests
2. **Create a new issue** - Use the feature request template
3. **Provide detailed description**:
   - Problem you're trying to solve
   - Proposed solution
   - Alternative approaches considered

### Feature Request Template

```markdown
**Feature Description**
Brief description of the feature

**Problem Statement**
What problem does this feature solve?

**Proposed Solution**
How should this feature work?

**Alternatives Considered**
What other approaches did you consider?

**Additional Context**
Any other relevant information
```

## Security Vulnerabilities

### Reporting Security Issues

For security vulnerabilities, please do **NOT** open a public issue. Instead:

1. **Email us**: security@smartcontractanalyzer.com
2. **Use PGP**: Our public key is available on our website
3. **Wait for response**: We'll respond within 48 hours

### Security Review Process

1. **Initial assessment** - Triage and prioritize
2. **Internal review** - Technical evaluation
3. **Fix development** - Patch implementation
4. **Testing** - Comprehensive testing
5. **Disclosure** - Coordinated disclosure timeline

## Community Guidelines

### Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please:

- Be respectful and professional
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Be patient with different perspectives

### Getting Help

- **GitHub Issues** - For bug reports and feature requests
- **Discussions** - For general questions and ideas
- **Discord** - For real-time chat and community support
- **Email** - For private or sensitive matters

### Recognition

Contributors are recognized in:

- **README.md** - Major contributors section
- **CHANGELOG.md** - Release notes and credits
- **Contributors.md** - Detailed contributor list
- **GitHub Stars** - Repository recognition

## Development Guidelines

### Adding New Vulnerability Patterns

When adding new detection patterns:

1. **Create test cases** in `tests/test_patterns/`
2. **Implement detection** in appropriate analyzer module
3. **Add documentation** in `docs/patterns/`
4. **Update examples** with test contracts

Example:
```python
# In analyzer.py
def detect_new_vulnerability(self, code: str) -> List[Finding]:
    pattern = r'vulnerability_pattern'
    matches = re.finditer(pattern, code)
    
    findings = []
    for match in matches:
        finding = Finding(
            title="New Vulnerability",
            severity=Severity.HIGH,
            line_number=code[:match.start()].count('\n') + 1,
            description="Description of the vulnerability",
            recommendation="How to fix it"
        )
        findings.append(finding)
    
    return findings
```

### Adding Machine Learning Features

When adding ML capabilities:

1. **Feature extraction** in `ml_detector.py`
2. **Model training** with proper validation
3. **Performance metrics** and evaluation
4. **Explainability** for model decisions

### GUI Development

When modifying the GUI:

1. **Follow Dark Mode theme** - Use existing color scheme
2. **Maintain consistency** - Use similar patterns
3. **Test accessibility** - Ensure keyboard navigation
4. **Responsive design** - Handle different screen sizes

## Release Process

### Version Management

We follow [Semantic Versioning](https://semver.org/):

- **Major version** (X.0.0) - Breaking changes
- **Minor version** (X.Y.0) - New features
- **Patch version** (X.Y.Z) - Bug fixes

### Release Checklist

1. **Update version** in all relevant files
2. **Update CHANGELOG.md**
3. **Run full test suite**
4. **Create release tag**
5. **Build executables**
6. **Update documentation**
7. **Publish release**

## Questions?

If you have any questions about contributing:

- Check our [FAQ](docs/FAQ.md)
- Search existing [Issues](https://github.com/nex2s21/SmartContractAnalizer/issues)
- Start a [Discussion](https://github.com/nex2s21/SmartContractAnalizer/discussions)
- Contact us at contribute@smartcontractanalyzer.com

---

Thank you for contributing to Smart Contract Analyzer! Your contributions help make blockchain security more accessible to everyone.
