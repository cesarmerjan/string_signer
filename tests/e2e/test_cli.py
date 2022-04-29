import subprocess
import unittest


class TestStringSigner(unittest.TestCase):
    def setUp(self):
        self.message = "Test message."
        self.sign_message = (
            "Test message.:sha256:bVIv9ULz:2ddK0Yu11N33fpVmUp69-TV6Xnanpch9p91U6YSHTnU"
        )
        self.secret_key = "hard to guess"

        self.command = "python3 -m src.string_signer {option} '{data}' '{secret_key}' {salt_length} {hash_algorithm}"

    def test_cli_encode_data(self):
        command = self.command.format(
            option="s",
            data=self.message,
            secret_key=self.secret_key,
            salt_length="",
            hash_algorithm="",
        )
        output = subprocess.check_output(command, shell=True).decode().strip()
        self.assertTrue(output)
        self.assertEqual(len(output.split(":")), 4)

    def test_cli_decode_data(self):
        command = self.command.format(
            option="u",
            data=self.sign_message,
            secret_key=self.secret_key,
            salt_length="",
            hash_algorithm="",
        )
        output = subprocess.check_output(command, shell=True).decode().strip()
        self.assertTrue(output)
        self.assertEqual(len(output.split(":")), 1)

    def test_cli_enode_data_with_custom_salt_length(self):
        command = self.command.format(
            option="s",
            data=self.message,
            secret_key=self.secret_key,
            salt_length="--salt_length 100",
            hash_algorithm="",
        )
        output = subprocess.check_output(command, shell=True).decode().strip()
        self.assertTrue(output)
        self.assertEqual(len(output.split(":")[2]), 100)
