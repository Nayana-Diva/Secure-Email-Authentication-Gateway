# Secure Email Authentication Gateway

A web-based email authentication testing system that demonstrates three important email security protocols: SPF, DKIM, and DMARC.

## Overview

The Secure Email Authentication Gateway provides a local web interface for generating demo emails and analyzing email authentication results.

It uses Python-based authentication modules and a Flask dashboard to demonstrate how email authentication checks work.

## Features

- Web-based security dashboard
- Demo email generation
- DKIM email signing using RSA keys
- SPF authentication checking
- DKIM signature verification
- DMARC policy and authentication checking
- Email header parsing
- Combined email authentication analysis
- Automated test suite

## Technologies Used

- Python
- Flask
- HTML, CSS and JavaScript
- DKIMpy
- dnspython
- Cryptography
- Pytest

## Project Structure

```text
Secure-Email-Authentication-Gateway/
│
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── src/
│   ├── authentication.py
│   ├── dkim_checker.py
│   ├── dmarc_checker.py
│   ├── header_parser.py
│   └── spf_checker.py
│
├── templates/
│   └── index.html
│
├── static/
│   ├── style.css
│   └── script.js
│
├── tests/
│   ├── test_authentication.py
│   ├── test_dkim.py
│   ├── test_dmarc.py
│   ├── test_header_parser.py
│   └── test_spf.py
│
├── samples/
├── screenshots/
└── keys/
```

The `keys/` directory contains locally generated cryptographic keys and is excluded from Git tracking.

## Installation

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd Secure-Email-Authentication-Gateway
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the environment

Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

## Running the Application

Start the Flask application:

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

## Application Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Loads the dashboard |
| `/api/demo-email` | POST | Generates a signed demo email |
| `/api/analyze` | POST | Analyzes an email |

## Running Tests

Execute the automated test suite:

```bash
python -m pytest tests -v
```

The tests cover authentication, DKIM, DMARC, SPF and email header parsing.

## Project Limitations

- The application is designed for local demonstration and testing.
- The demo uses `example.com` as a controlled test domain.
- Local testing does not establish real-world authentication for a public email domain.
- Production deployment would require appropriate DNS configuration and mail-server integration.

## Future Enhancements

- Integration with real email servers
- Enhanced authentication reporting
- Support for additional email security mechanisms
- Improved security analytics and monitoring
- Deployment in a production environment

## Disclaimer

This project is developed for educational, demonstration and academic assignment purposes. It is not intended to replace a production email security gateway.
