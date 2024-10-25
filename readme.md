# 🔒 Password Strength Analyzer

A Streamlit-based web application that analyzes password strength using multiple security criteria, including length, complexity, entropy, pattern detection, and breach checking through the HaveIBeenPwned API.

## 🚀 Features

- Real-time password strength analysis
- Multiple security checks:
  - Password length evaluation
  - Character complexity analysis
  - Entropy calculation
  - Common pattern detection
  - Data breach checking via HaveIBeenPwned API
- Interactive web interface with detailed feedback
- Secure password handling (passwords are never stored)
- Visual strength indicators
- Detailed improvement suggestions

## 📋 Prerequisites

- Python 3.8+
- Streamlit
- Internet connection (for HaveIBeenPwned API)

## 🔧 Installation

1. Clone the repository
```bash
git clone https://github.com/yourusername/password-strength-analyzer.git
cd password-strength-analyzer
```

2. Create and activate virtual environment (recommended)
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

## 🎮 Usage

1. Run the Streamlit application:
```bash
streamlit run app.py
```

2. Open your browser and navigate to the URL shown in the terminal (typically http://localhost:8501)

3. Enter a password to analyze its strength

## 📦 Project Structure

```
password-strength-analyzer/
│
├── app.py                 # Main application file
├── requirements.txt       # Project dependencies
├── .env.example          # Example environment variables
├── .gitignore            # Git ignore rules
├── LICENSE               # Project license
├── README.md            # Project documentation
│
├── tests/               # Test files
│   ├── __init__.py
│   └── test_analyzer.py
│
└── docs/               # Additional documentation
    ├── API.md
    └── DEVELOPMENT.md
```

## 🧪 Running Tests

```bash
pytest tests/
```

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) first.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔒 Security

- Passwords are never stored or transmitted to any external service except for the HaveIBeenPwned API (using k-anonymity)
- Only the first 5 characters of the password hash are sent to the API
- All processing is done locally in the browser

## 👥 Authors

* Your Name - *Initial work*

## 🙏 Acknowledgments

* [HaveIBeenPwned](https://haveibeenpwned.com/) for the password breach API
* Streamlit team for the excellent framework
