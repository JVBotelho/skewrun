# Contributing to Skewrun

Thank you for your interest in contributing to `skewrun`! We welcome bug reports, feature requests, and code contributions.

## Reporting Bugs and Requesting Features

Please use the [GitHub Issues](https://github.com/JVBotelho/skewrun/issues) tracker to report bugs or request new features.
Before opening a new issue, please search existing issues to see if it has already been reported.

If you are reporting a security vulnerability, please follow the instructions in our [Security Policy](SECURITY.md).

## Development Process

1. Fork the repository and create a new branch for your feature or bug fix.
2. Make your changes and commit them with descriptive commit messages.
3. Push your branch to your fork.
4. Open a Pull Request (PR) against the `main` branch of this repository.

## Requirements for Acceptable Contributions

To ensure code quality and consistency, all pull requests must meet the following requirements:

* **Code Formatting:** The code must be formatted using `rustfmt`. You can format your code by running:
  ```bash
  cargo fmt
  ```
* **Linting:** The code must pass all `clippy` checks without warnings. Run:
  ```bash
  cargo clippy --workspace -- -D warnings
  ```
* **Testing Policy:** We have a strict policy for tests. **Any major new functionality must include automated tests** (unit tests, integration tests, or fuzz targets) covering the new code.
* **Pass CI:** Your PR must pass all checks in our Continuous Integration (CI) pipeline, which includes tests, linting, and dependency audits. Run tests locally before submitting:
  ```bash
  cargo test --workspace
  ```

## Setting up the Development Environment

You will need a standard Rust toolchain. We recommend using `rustup`.
No other external dependencies are required for standard development.

```bash
git clone https://github.com/JVBotelho/skewrun
cd skewrun
cargo build
cargo test
```
