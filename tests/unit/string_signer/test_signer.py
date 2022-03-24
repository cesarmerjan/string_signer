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
        self.known_salt = "salt"
        self.expected_key_to_known_salt = b"wOd\xf5\xee\x83\xed\xb9\xbda&\xd4t\x1e<\x9f0\xd2\x1a\xeb\xa2\xb6\xac\x87\x13OS\xa9\xf9\xca\x16\xe2"
        self.signature_to_known_salt = b"D.}\x98.\xc2f\xe7#\tb3\xb9\xda\x17!0\xa8\x14Nn8i\xa7\x1d\xe51Y\xb4\x92;\xca"

    def test_for_signer_secret_key_set_error(self):
        with self.assertRaises(InvalidSecretKey):
            StringSigner("")
        with self.assertRaises(InvalidSecretKey):
            StringSigner(None)
        with self.assertRaises(InvalidSecretKey):
            StringSigner(1)
        with self.assertRaises(InvalidSecretKey):
            StringSigner([])
        with self.assertRaises(InvalidSecretKey):
            StringSigner({})
        with self.assertRaises(InvalidSecretKey):
            StringSigner(set([]))
        with self.assertRaises(InvalidSecretKey):
            StringSigner(1.2)
        with self.assertRaises(InvalidSecretKey):
            StringSigner(lambda: "function")
        with self.assertRaises(InvalidSecretKey):
            StringSigner(type("MyClass", (object,), {}))
        with self.assertRaises(InvalidSecretKey):
            StringSigner(True)

    def test_for_signer_hash_algorithm_set_error(self):
        with self.assertRaises(InvalidAlgorithm):
            StringSigner(self.secret_key, hash_algorithm="wrong")
        with self.assertRaises(InvalidAlgorithm):
            StringSigner(self.secret_key, 1)
        with self.assertRaises(InvalidAlgorithm):
            StringSigner(self.secret_key, [])
        with self.assertRaises(InvalidAlgorithm):
            StringSigner(self.secret_key, {})
        with self.assertRaises(InvalidAlgorithm):
            StringSigner(self.secret_key, set([]))
        with self.assertRaises(InvalidAlgorithm):
            StringSigner(self.secret_key, 1.2)
        with self.assertRaises(InvalidAlgorithm):
            StringSigner(self.secret_key, lambda: "function")
        with self.assertRaises(InvalidAlgorithm):
            StringSigner(self.secret_key, type("MyClass", (object,), {}))
        with self.assertRaises(InvalidAlgorithm):
            StringSigner(self.secret_key, True)

    def test_for_signer_separator_set_error(self):
        with self.assertRaises(InvalidSeparator):
            StringSigner(self.secret_key, separator="a")
        with self.assertRaises(InvalidSeparator):
            StringSigner(self.secret_key, separator=1)
        with self.assertRaises(InvalidSeparator):
            StringSigner(self.secret_key, separator=[])
        with self.assertRaises(InvalidSeparator):
            StringSigner(self.secret_key, separator={})
        with self.assertRaises(InvalidSeparator):
            StringSigner(self.secret_key, separator=set([]))
        with self.assertRaises(InvalidSeparator):
            StringSigner(self.secret_key, separator=1.2)
        with self.assertRaises(InvalidSeparator):
            StringSigner(self.secret_key, separator=lambda: "function")
        with self.assertRaises(InvalidSeparator):
            StringSigner(self.secret_key, separator=type("MyClass", (object,), {}))
        with self.assertRaises(InvalidSeparator):
            StringSigner(self.secret_key, separator=True)

    def test_for_signer_salt_lenght_set_error(self):
        with self.assertRaises(InvalidSaltLength):
            StringSigner(self.secret_key, salt_length=0)
        with self.assertRaises(InvalidSaltLength):
            StringSigner(self.secret_key, salt_length="8")
        with self.assertRaises(InvalidSaltLength):
            StringSigner(self.secret_key, salt_length=[])
        with self.assertRaises(InvalidSaltLength):
            StringSigner(self.secret_key, salt_length={})
        with self.assertRaises(InvalidSaltLength):
            StringSigner(self.secret_key, salt_length=set([]))
        with self.assertRaises(InvalidSaltLength):
            StringSigner(self.secret_key, salt_length=1.2)
        with self.assertRaises(InvalidSaltLength):
            StringSigner(self.secret_key, salt_length=lambda: "function")
        with self.assertRaises(InvalidSaltLength):
            StringSigner(self.secret_key, salt_length=type("MyClass", (object,), {}))
        with self.assertRaises(InvalidSaltLength):
            StringSigner(self.secret_key, salt_length=True)

    def test_unsign_string_type_error(self):
        string_signer = StringSigner(self.secret_key)

        signed_message = string_signer.sign(self.message)

        with self.assertRaises(InvalidSignedString):
            string_signer.unsign(signed_message.encode())

        with self.assertRaises(InvalidSignedString):
            string_signer.unsign(b"OK")
        with self.assertRaises(InvalidSignedString):
            string_signer.unsign(1)
        with self.assertRaises(InvalidSignedString):
            string_signer.unsign([])
        with self.assertRaises(InvalidSignedString):
            string_signer.unsign({})
        with self.assertRaises(InvalidSignedString):
            string_signer.unsign(set([]))
        with self.assertRaises(InvalidSignedString):
            string_signer.unsign(1.2)
        with self.assertRaises(InvalidSignedString):
            string_signer.unsign(lambda: "function")
        with self.assertRaises(InvalidSignedString):
            string_signer.unsign(type("MyClass", (object,), {}))
        with self.assertRaises(InvalidSignedString):
            string_signer.unsign(True)

    def test_sing_string_error(self):

        string_signer = StringSigner(self.secret_key)

        with self.assertRaises(InvalidString):
            string_signer.sign(b"OK")
        with self.assertRaises(InvalidString):
            string_signer.sign(1)
        with self.assertRaises(InvalidString):
            string_signer.sign([])
        with self.assertRaises(InvalidString):
            string_signer.sign({})
        with self.assertRaises(InvalidString):
            string_signer.sign(set([]))
        with self.assertRaises(InvalidString):
            string_signer.sign(1.2)
        with self.assertRaises(InvalidString):
            string_signer.sign(lambda: "function")
        with self.assertRaises(InvalidString):
            string_signer.sign(type("MyClass", (object,), {}))
        with self.assertRaises(InvalidString):
            string_signer.sign(True)

    def test_string_to_bytes_method(self):
        string_signer = StringSigner(self.secret_key)
        byte_message = string_signer._string_to_bytes(self.message)
        self.assertEqual(byte_message, self.message.encode())

    def test_generate_salt_method(self):
        string_signer = StringSigner(self.secret_key)
        salt = string_signer._generate_salt()
        self.assertEqual(len(salt), string_signer.salt_length)
        for i in salt:
            self.assertIn(i, string_signer.SALT_CHARS)

    def test_generate_key_method(self):
        string_signer = StringSigner(self.secret_key)
        key = string_signer._generate_key(self.known_salt)
        self.assertEqual(key, self.expected_key_to_known_salt)

    def test_generate_signature_method(self):
        string_signer = StringSigner(self.secret_key)
        key = string_signer._generate_key(self.known_salt)
        signature = string_signer._generate_signature(self.message, key)
        self.assertEqual(signature, self.signature_to_known_salt)

    def test_structure_signed_string_method(self):
        string_signer = StringSigner(self.secret_key)

        expected_signature = "message:sha256:salt:signature"

        signature = string_signer._structure_signed_string(
            "message",
            "salt",
            "signature"
        )

        self.assertEqual(signature, expected_signature)

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

    def test_for_error_in_signer_secret_key_change(self):
        string_signer = StringSigner(self.secret_key)

        signed_message = string_signer.sign(self.message)

        string_signer = StringSigner("wrong secret")

        with self.assertRaises(InvalidSignature):
            string_signer.unsign(signed_message)

    def test_encode_signature(self):
        string_signer = StringSigner(self.secret_key)

        signature = "a-signature".encode()

        encoded_signature = string_signer._encode_signature(signature)
        self.assertEqual(encoded_signature, "YS1zaWduYXR1cmU")

    def test_encode_signature_error(self):
        string_signer = StringSigner(self.secret_key)

        signature = "a-signature"
        with self.assertRaises(InvalidSignatureType):
            string_signer._encode_signature(signature)
