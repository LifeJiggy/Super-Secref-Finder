# Contributing to Super Secref Finder

Thank you for your interest in contributing to Super Secref Finder! We welcome contributions from the community to help improve this security scanning tool.

## How to Contribute

### 1. Fork the Repository

Start by forking the repository on GitHub to your own account.

### 2. Clone Your Fork

```bash
git clone https://github.com/Lifejiggy/Super-Secref-Finder.git
cd Super-Secref-Finder
```

### 3. Create a Feature Branch

Create a new branch for your contribution:

```bash
git checkout -b feature/your-feature-name
```

### 4. Set Up Development Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -e ".[dev]"
```

### 5. Make Your Changes

- Write clear, concise code
- Add tests for new features
- Update documentation as needed
- Follow the existing code style

### 6. Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html
```

### 7. Commit Your Changes

```bash
git add .
git commit -m "Add your descriptive commit message"
```

### 8. Push to Your Fork

```bash
git push origin feature/your-feature-name
```

### 9. Create a Pull Request

Go to the original repository and create a pull request from your feature branch.

## Development Guidelines

### Code Style

- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Keep functions small and focused

### Testing

- Write unit tests for new functionality
- Ensure all tests pass before submitting
- Test edge cases and error conditions

### Documentation

- Update README.md for significant changes
- Add inline comments for complex logic
- Update docstrings when changing function behavior

## Types of Contributions

### Bug Fixes

- Fix reported bugs
- Add regression tests
- Update documentation if needed

### New Features

- Discuss new features in issues first
- Implement with proper tests
- Update documentation

### Pattern Improvements

- Add new regex patterns for secret detection
- Improve existing patterns
- Validate patterns don't create false positives

### Performance Improvements

- Optimize scanning algorithms
- Improve multi-threading implementation
- Reduce memory usage

## Reporting Issues

When reporting bugs, please include:

- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Error messages/logs

## Code of Conduct

Please be respectful and constructive in all interactions. We aim to create a welcoming environment for all contributors.

## License

By contributing to this project, you agree that your contributions will be licensed under the same MIT License that covers the project.

Thank you for contributing to Super Secref Finder!