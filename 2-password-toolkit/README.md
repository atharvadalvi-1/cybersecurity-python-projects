# Password Strength Checker & Hash Cracking Demo

Educational Python tool covering password security basics.

## Features
- Strength checker (length, character variety, common-password check) with improvement tips
- SHA-256 hashing demo
- Dictionary attack demo showing how weak passwords are cracked
- Salting demo using PBKDF2 to show the defence

## Usage
```bash
python password_toolkit.py
```

## Key lessons
- Hashes are one-way, but identical inputs give identical hashes.
- Weak passwords fall to dictionary attacks in milliseconds.
- Salting + slow hashing (PBKDF2/bcrypt/argon2) is the correct way to store passwords.

## Future improvements
Check against the HaveIBeenPwned API, add bcrypt, GUI.
