"""
Password Strength Checker + Hashing / Dictionary Attack Demo
Educational: shows why weak passwords and unsalted hashes are dangerous.
"""
import re
import hashlib
import os

COMMON_PASSWORDS = {"password", "123456", "12345678", "qwerty", "abc123", "admin",
                    "letmein", "welcome", "iloveyou", "monkey", "dragon", "password1"}

def check_strength(pw):
    score, tips = 0, []
    if len(pw) >= 12: score += 2
    elif len(pw) >= 8: score += 1
    else: tips.append("Use at least 8 characters (12+ is better)")
    if re.search(r"[a-z]", pw): score += 1
    else: tips.append("Add lowercase letters")
    if re.search(r"[A-Z]", pw): score += 1
    else: tips.append("Add uppercase letters")
    if re.search(r"\d", pw): score += 1
    else: tips.append("Add numbers")
    if re.search(r"[^A-Za-z0-9]", pw): score += 1
    else: tips.append("Add special characters")
    if pw.lower() in COMMON_PASSWORDS:
        score = 0; tips.append("This is a very common password!")
    label = "Weak" if score <= 2 else "Medium" if score <= 4 else "Strong"
    return label, score, tips

def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()

def dictionary_attack(target_hash, wordlist):
    """Hash every word and compare - this is how weak passwords get cracked."""
    for word in wordlist:
        if sha256(word) == target_hash:
            return word
    return None

def salted_hash(pw):
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 100_000)
    return salt.hex(), h.hex()

def demo():
    print("=== Hashing demo ===")
    pw = "password1"
    h = sha256(pw)
    print(f"SHA-256('{pw}') = {h}")
    print("Same input always gives the same hash (so attackers can precompute).\n")

    print("=== Dictionary attack demo ===")
    cracked = dictionary_attack(h, sorted(COMMON_PASSWORDS))
    print(f"Cracked: {cracked!r}\n" if cracked else "Not found in wordlist\n")

    print("=== Salting demo (the fix) ===")
    for _ in range(2):
        salt, hashed = salted_hash(pw)
        print(f"salt={salt[:12]}...  hash={hashed[:24]}...")
    print("Same password, different hash each time -> precomputed tables are useless.")

if __name__ == "__main__":
    print("1) Check password strength\n2) Run hashing/cracking demo")
    choice = input("Choose: ").strip()
    if choice == "1":
        label, score, tips = check_strength(input("Enter password: "))
        print(f"\nStrength: {label} ({score}/6)")
        for t in tips: print(" -", t)
    else:
        demo()
