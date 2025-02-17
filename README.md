# 🔐 Vaultify 2.0

A secure and simple command-line password manager written in Python. It allows users to store, retrieve, update, and delete passwords securely using encryption and a master password.

## 🌟 Security Features

- **Master Password**: Required to access stored passwords.
- **Password Encryption**: All stored passwords are encrypted using `Fernet` encryption.
- **Password Hashing**: Master password is securely hashed using `bcrypt`.
- **Strong Password Requirements**: Passwords must include at least 9 characters, an uppercase letter, a lowercase letter, a number, and a special character.
- **Password Visibility**: While entering the password the password will not be visible on the screen.
- **Password Confirmation**: Whenever you setup a master password , setup a new password , update password you are required to re enter the password to confirm the password . 

## 🛠 Installation

Ensure you have Python installed on your system.

1. Clone the repository:

```bash
git clone https://github.com/yourusername/password-manager-cli.git
cd password-manager-cli
```

2. Install dependencies:

```bash
pip install bcrypt cryptography
```

## Usage

Run the script using:

```bash
python Vaultify.py
```

### 🚀 First-time Setup
If running for the first time, you will be asked to create a master password. This password will be required to access stored passwords in future sessions.

### 🖥 Menu Options
- **Add a new password**: Store a password for a website.
- **Retrieve a password**: Retrieve a stored password.
- **Update a password**: Change a stored password.
- **Delete a password**: Remove a stored password.
- **Exit**: Close the application.



