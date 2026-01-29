# Legitify (Python Port)

<p align="center">
  <img src="https://raw.githubusercontent.com/Legit-Labs/legitify/main/images/logo.png" alt="Legitify Logo" width="200"/>
</p>

**Legitify** is a security posture analysis tool that scans your GitHub organizations and repositories for security misconfigurations and compliance violations. This is a **Python port** of the original [Legitify](https://github.com/Legit-Labs/legitify) tool (written in Go), maintaining core parity with its OPA-based policy engine.

## 🚀 Key Features

*   **Security Scanning**: Detects misconfigurations like missing branch protections, insecure webhook settings, and stale secrets.
*   **OPA Powered**: Uses Open Policy Agent (OPA) and Rego policies for flexible and auditable security rules.
*   **Comprehensive Coverage**: Scans Repositories, Organizations, Members, **Actions**, and **Runners**.
*   **Rich Output**: Provides clear, human-readable reports (Table, Markdown) with actionable remediation steps, or machine-parseable JSON.

## 🛠️ Installation

### Prerequisites
*   Python 3.9+
*   [OPA (Open Policy Agent)](https://www.openpolicyagent.org/docs/latest/#running-opa) executable in your system PATH or project root.

### Setup
1.  Clone the repository:
    ```bash
    git clone https://github.com/Ali190903/Legitify-Python.git
    cd Legitify-Python
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3.  Ensure `opa` is installed:
    ```bash
    opa version
    # If not found, download opa.exe and place it in this folder.
    ```

## 📖 Usage

Legitify requires a GitHub Personal Access Token (PAT) with `repo`, `read:org`, and `admin:org_hook` permissions.

### Basic Scan
Scan a GitHub organization:
```bash
python main.py analyze --org <YOUR_ORG_NAME> --token <YOUR_GITHUB_TOKEN>
```

### Scan Specific Repository
```bash
python main.py analyze --org <YOUR_ORG_NAME> --repo <REPO_NAME> --token <YOUR_GITHUB_TOKEN>
```

### Output Formats
Get the results in JSON format for integration with other tools:
```bash
python main.py analyze --org <YOUR_ORG_NAME> --output-format json --token <YOUR_GITHUB_TOKEN>
```

## 🧩 Policy & Architecture

This tool mirrors the architecture of the original Go implementation:

*   **Collectors**: Fetch data from GitHub via GraphQL and REST APIs.
*   **OPA Engine**: Evaluates the collected data against Rego policies located in `policies/`.
*   **Outputer**: Formats the violations for the user.

### Directory Structure
*   `cli/`: Command-line interface logic.
*   `internal/`: Core logic (Collectors, OPA Engine, Clients).
*   `policies/`: OPA Rego policies defining security rules.
*   `tests/`: Unit and integration tests.

## ⚠️ Disclaimer
This is a community port and is not officially affiliated with Legit Security. Use at your own risk.

## 📄 License
Distributed under the Apache 2.0 License. See `LICENSE` for more information.
