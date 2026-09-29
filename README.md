# MFA-Based Caesar Cipher Authentication System

A small Python command-line project that demonstrates **multi-factor authentication (MFA)**.
A user must pass two checks to log in: something they **know** (a password) and something they
**hold** (a secret shift key used to decode a one-time password).

> **Educational project.** The Caesar cipher is trivially breakable and must not be used to protect
> real accounts. It is used here to illustrate how a secret-key second factor works.

## How it works

1. **Register:** choose a username, a password (minimum 8 characters) and a secret shift key (1–25).
   The password is never stored directly. It is hashed with **PBKDF2-HMAC-SHA256** (100,000 iterations)
   using a random 16-byte salt.
2. **Factor 1 – password:** the entered password is hashed with the stored salt and compared to the stored hash.
3. **Factor 2 – OTP:** the system generates a random 6-digit OTP and shows it **Caesar-encrypted**
   using the user's shift key. The user decrypts it and types the result.
4. **Protections:** each OTP is valid for **60 seconds** and allows **3 attempts**, which slows down
   brute-force guessing.

## Run it

Requires Python 3.8+ and uses the standard library only.

```bash
python mfa_caesar_auth.py
```

## Run the tests

```bash
python -m unittest test_mfa_caesar_auth.py -v
```

## Project structure

```
mfa_caesar_auth.py        # registration, login, cipher and hashing logic
test_mfa_caesar_auth.py   # unit tests
users.json                # created at runtime (git-ignored)
```

## Known limitations and ideas for improvement

- The Caesar cipher has only 25 possible keys, so it is not secure. A real system would use
  TOTP (RFC 6238) or a hardware key.
- The OTP is printed to the terminal instead of being sent through a separate channel such as SMS or email.
- Lockout applies only to the current session. A persistent account lockout is a natural next step.
- Use `secrets` instead of `random` for OTP generation.

## Author

Yubaraj Das, B.Tech CSE (Cybersecurity), Dr. B.C. Roy Engineering College, Durgapur
