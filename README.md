# Password Security Tester

An educational tool for understanding password security through practical demonstrations of various hashing algorithms and cracking techniques.

## Overview
This project provides a Python-based password security testing tool that demonstrates how different password hashing algorithms protect (or fail to protect) user credentials. It's designed purely for educational purposes to help users understand why strong passwords matter and how password cracking works.

The tool supports:

- Comparing three different hashing methods: plaintext (no hashing), SHA-256, and bcrypt
- Performing dictionary attacks using common password lists
- Executing brute force attacks with configurable parameters
- Evaluating password strength without attempting to crack it
- Generating strong password suggestions
- Visualizing attack performance and security comparisons

## 🚨 Educational Use Only

This tool is designed for **educational purposes only**. Using password cracking techniques on systems or accounts without explicit permission is illegal and unethical. Always use these skills responsibly – to improve your own security and the security of systems you're authorized to test.

## Installation

### Prerequisites
- Python 3.6+
- pip (Python package manager)

### Dependencies
```bash
pip install -r requirements.txt
```
The main dependencies include:
- bcrypt
- matplotlib
- tqdm

### Dictionary File
For dictionary attacks, the tool uses a wordlist of common passwords. By default, it looks for `rockyou.txt` in the current directory. You can either:

1. Download a copy of rockyou.txt from security resources online
2. Specify a different dictionary file using the `--dict-file` parameter
3. Run without a dictionary file (the tool will use a small built-in sample)

## Usage
### Interactive Mode
The easiest way to use the tool is in interactive mode:

```bash
python password_tester.py -i
```

This will present you with a menu of options to explore different features of the tool.

### Command Line Options

```bash
python password_tester.py --help
```

Example commands:

```bash
# Test a password's strength without cracking attempts
python password_tester.py --evaluate --password "your_password_here"

# Get a suggested secure password
python password_tester.py --suggest

# Run a dictionary attack (prompts for password)
python password_tester.py --attack dictionary --max-attempts 10000

# Run a brute force attack with a specified password
python password_tester.py --attack brute --password "test123" --max-attempts 100000

# Use a custom dictionary file
python password_tester.py --dict-file my_wordlist.txt --attack dictionary
```

## Features

### 1. Password Strength Evaluation

The tool evaluates password strength based on multiple criteria:
- Length (longer is better)
- Character variety (uppercase, lowercase, numbers, special characters)
- Common patterns or dictionary words
- Sequential or repeated characters

Each password receives a score (0-100) and actionable feedback.

### 2. Hashing Algorithm Comparison

Compares three different approaches to password storage:
- **Plaintext**: No hashing (baseline for comparison)
- **SHA-256**: Fast cryptographic hash function
- **bcrypt**: Slow, purpose-built password hashing function with salting

### 3. Attack Simulations

#### Dictionary Attack
Tests passwords against a list of commonly used passwords, demonstrating why using common passwords is dangerous.

#### Brute Force Attack
Attempts all possible combinations of characters up to a specified length, showing how complexity and length affect crack time.

### 4. Visualization

Generates visualizations that show:
- Hash generation time for different algorithms
- Password cracking time comparison
- Password analysis with strengths and weaknesses

## Understanding the Results

When comparing algorithms, pay attention to:

1. **Hash Generation Time**: bcrypt is intentionally slow, which is a security feature that makes large-scale attacks more difficult.

2. **Cracking Success**: Which algorithms were successfully cracked and how quickly.

3. **Number of Attempts**: How many password attempts were required before finding a match.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

Some ideas for contributions:
- Add support for additional hash algorithms (Argon2, scrypt)
- Improve visualization capabilities
- Add more sophisticated password strength evaluation metrics
- Create a web interface

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author
Kolamide Idowu

## Acknowledgments

- This project was inspired by the need to understand and demonstrate password security concepts in a practical way
- Special thanks to the cybersecurity community for raising awareness about the importance of proper password practices

## Learn More

For more information about password security best practices, check out:
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Have I Been Pwned](https://haveibeenpwned.com/) - Check if your accounts have been compromised

---

Remember: The best security comes from understanding how attacks work and implementing proper defenses. Stay curious, stay secure!
