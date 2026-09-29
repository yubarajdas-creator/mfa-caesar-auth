"""
MFA-Based Caesar Cipher Authentication System (educational project)

Factor 1: password (stored as a salted PBKDF2 hash, never in plain text)
Factor 2: one-time password (OTP) sent as a Caesar-cipher-encrypted code;
          the user decrypts it with their secret shift key and enters it.

Note: the Caesar cipher is NOT secure and is used here only to demonstrate
the idea of a secret-key second factor. Standard library only.
"""
import hashlib
import json
import os
import random
import string
import time

DB_FILE = "users.json"
OTP_LENGTH = 6
OTP_VALIDITY_SECONDS = 60
MAX_ATTEMPTS = 3


# ---------- Caesar cipher ----------
def caesar_encrypt(text, shift):
    result = ""
    for ch in text:
        if ch.isdigit():
            result += str((int(ch) + shift) % 10)
        elif ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result += chr((ord(ch) - base + shift) % 26 + base)
        else:
            result += ch
    return result


def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


# ---------- helpers ----------
def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000).hex()


def load_users():
    if os.path.exists(DB_FILE):
        with open(DB_FILE) as f:
            return json.load(f)
    return {}


def save_users(users):
    with open(DB_FILE, "w") as f:
        json.dump(users, f, indent=2)


def generate_otp():
    return "".join(random.choice(string.digits) for _ in range(OTP_LENGTH))


# ---------- registration ----------
def register():
    users = load_users()
    username = input("Choose username: ").strip()
    if not username or username in users:
        print("Invalid or already taken username.")
        return
    password = input("Choose password: ")
    if len(password) < 8:
        print("Password must be at least 8 characters.")
        return
    try:
        shift = int(input("Choose secret shift key (1-25): "))
    except ValueError:
        print("Shift key must be a number.")
        return
    if not 1 <= shift <= 25:
        print("Shift key must be between 1 and 25.")
        return
    salt = os.urandom(16)
    users[username] = {
        "salt": salt.hex(),
        "password_hash": hash_password(password, salt),
        "shift": shift,
    }
    save_users(users)
    print("Registration successful.")


# ---------- login ----------
def login():
    users = load_users()
    username = input("Username: ").strip()
    password = input("Password: ")
    user = users.get(username)

    # Factor 1: password
    if not user or hash_password(password, bytes.fromhex(user["salt"])) != user["password_hash"]:
        print("Invalid username or password.")
        return

    # Factor 2: Caesar-encrypted OTP
    otp = generate_otp()
    encrypted = caesar_encrypt(otp, user["shift"])
    issued_at = time.time()
    print(f"\nEncrypted OTP sent: {encrypted}")
    print(f"(Decrypt it with your secret shift key. Valid for {OTP_VALIDITY_SECONDS}s.)")

    for attempt in range(1, MAX_ATTEMPTS + 1):
        entered = input(f"Enter decrypted OTP (attempt {attempt}/{MAX_ATTEMPTS}): ").strip()
        if time.time() - issued_at > OTP_VALIDITY_SECONDS:
            print("OTP expired. Login failed.")
            return
        if entered == otp:
            print(f"Access granted. Welcome, {username}!")
            return
        print("Wrong OTP.")
    print("Too many failed attempts. Account locked for this session.")


def main():
    while True:
        print("\n1. Register  2. Login  3. Exit")
        choice = input("Choose: ").strip()
        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            break


if __name__ == "__main__":
    main()
