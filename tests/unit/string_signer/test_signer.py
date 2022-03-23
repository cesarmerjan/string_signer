import unittest

from src.string_signer import StringSigner
from src.string_signer.exceptions import (
    InvalidAlgorithm,
    InvalidSaltLength,
    InvalidSecretKey,
    InvalidSeparator,
    InvalidSignature,
    InvalidSignatureStructure,
    InvalidSignatureType,
    InvalidSignedString,
    InvalidString,
)


class TestStringSigner(unittest.TestCase):
    def setUp(self):
        self.message = "Test message."
        self.secret_key = "hard to guess"

    def test_sign_and_unsign(self):
        string_signer = StringSigner(self.secret_key)

        signed_message = string_signer.sign(self.message)
        message, hash_algorithm, salt, signature = signed_message.split(
            string_signer.separator
        )

        self.assertEqual(message, self.message)
        self.assertEqual(hash_algorithm, string_signer.hash_algorithm)
        self.assertEqual(len(salt), string_signer.salt_length)

        string_signer = StringSigner(self.secret_key)

        self.assertEqual(string_signer.unsign(signed_message), self.message)

    def test_for_invalid_signature_error(self):
        string_signer = StringSigner(self.secret_key)

        signed_message = string_signer.sign(self.message)
        message, hash_algorithm, salt, signature = signed_message.split(
            string_signer.separator
        )

        message_changed = self.message + "worg"

        signed_message_changed = f"{string_signer.separator}".join(
            [message_changed, hash_algorithm, salt, signature]
        )

        with self.assertRaises(InvalidSignature):
            string_signer.unsign(signed_message_changed)

    def test_for_invalid_signature_structure_error(self):
        string_signer = StringSigner(self.secret_key)

        signed_message = string_signer.sign(self.message)
        signed_message = signed_message.replace(":", "$")

        with self.assertRaises(InvalidSignatureStructure):
            string_signer.unsign(signed_message)

        signed_message = string_signer.sign(self.message)[0:2]

        with self.assertRaises(InvalidSignatureStructure):
            string_signer.unsign(signed_message)

    def test_with_signed_message_is_signed(self):
        string_signer = StringSigner(self.secret_key)

        signed_message = string_signer.sign(self.message)

        self.assertTrue(string_signer.is_signed(signed_message))

    def test_with_unsigned_message_is_unsigned(self):
        string_signer = StringSigner(self.secret_key)
        self.assertFalse(string_signer.is_signed(self.message))

    def test_with_for_error_in_signer_secret_key_change(self):
        string_signer = StringSigner(self.secret_key)

        signed_message = string_signer.sign(self.message)

        string_signer = StringSigner("wrong secret")

        with self.assertRaises(InvalidSignature):
            string_signer.unsign(signed_message)

    def test_for_signer_salt_lenght_set_error(self):
        with self.assertRaises(InvalidSaltLength):
            StringSigner(self.secret_key, salt_length=0)
        with self.assertRaises(InvalidSaltLength):
            StringSigner(self.secret_key, salt_length="8")
        with self.assertRaises(InvalidSaltLength):
            StringSigner(self.secret_key, salt_length="five")

    def test_for_signer_secret_key_set_error(self):
        with self.assertRaises(InvalidSecretKey):
            StringSigner("")
        with self.assertRaises(InvalidSecretKey):
            StringSigner(None)
        with self.assertRaises(InvalidSecretKey):
            StringSigner(34940237208)

    def test_for_signer_hash_algorithm_set_error(self):
        with self.assertRaises(InvalidAlgorithm):
            StringSigner(self.secret_key, hash_algorithm="wrong")

    def test_for_signer_separator_set_error(self):
        with self.assertRaises(InvalidSeparator):
            StringSigner(self.secret_key, separator="a")

    def test_unsign_string_type_error(self):
        string_signer = StringSigner(self.secret_key)

        signed_message = string_signer.sign(self.message)

        with self.assertRaises(InvalidSignedString):
            string_signer.unsign(signed_message.encode())

    def test_sing_string_error(self):

        string_signer = StringSigner(self.secret_key)

        with self.assertRaises(InvalidString):
            string_signer.sign(self.message.encode())

    def test_encode_signature(self):
        string_signer = StringSigner(self.secret_key)

        signature = "a-signature".encode()

        encoded_signature = string_signer._encode_signature(signature)
        self.assertAlmostEqual(encoded_signature, "YS1zaWduYXR1cmU")

    def test_encode_signature_error(self):
        string_signer = StringSigner(self.secret_key)

        signature = "a-signature"
        with self.assertRaises(InvalidSignatureType):
            string_signer._encode_signature(signature)
