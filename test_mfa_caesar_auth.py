import os
import unittest

import mfa_caesar_auth as m


class CaesarTests(unittest.TestCase):
    def test_round_trip_digits(self):
        for shift in range(1, 26):
            self.assertEqual(m.caesar_decrypt(m.caesar_encrypt("493021", shift), shift), "493021")

    def test_round_trip_letters(self):
        self.assertEqual(m.caesar_decrypt(m.caesar_encrypt("Hello, World", 7), 7), "Hello, World")

    def test_encryption_changes_text(self):
        self.assertNotEqual(m.caesar_encrypt("123456", 3), "123456")


class HashTests(unittest.TestCase):
    def test_same_input_same_hash(self):
        salt = os.urandom(16)
        self.assertEqual(m.hash_password("secret123", salt), m.hash_password("secret123", salt))

    def test_different_salt_different_hash(self):
        self.assertNotEqual(m.hash_password("secret123", b"a" * 16), m.hash_password("secret123", b"b" * 16))

    def test_wrong_password_different_hash(self):
        salt = os.urandom(16)
        self.assertNotEqual(m.hash_password("secret123", salt), m.hash_password("secret124", salt))


class OtpTests(unittest.TestCase):
    def test_otp_length_and_digits(self):
        otp = m.generate_otp()
        self.assertEqual(len(otp), m.OTP_LENGTH)
        self.assertTrue(otp.isdigit())


if __name__ == "__main__":
    unittest.main()
