import argparse
import unittest

from src.string_signer.__main__ import (add_arguments, create_parser, main,
                                        process_data)


class TestStringSigner(unittest.TestCase):
    def setUp(self):
        self.message = "Test message."
        self.sign_message = (
            "Test message.:sha256:bVIv9ULz:2ddK0Yu11N33fpVmUp69-TV6Xnanpch9p91U6YSHTnU"
        )
        self.secret_key = "hard to guess"

        self.program = "test"
        self.usage = "test"
        self.description = "test"
        self.epilog = "test"
        self.valid_options = ("s", "u")

    def test_create_parser(self):
        parser = create_parser(self.program, self.usage, self.description, self.epilog)
        self.assertIsInstance(parser, argparse.ArgumentParser)

    def test_add_args_to_parcer(self):
        parser = create_parser(self.program, self.usage, self.description, self.epilog)
        add_arguments(parser)

    def test_parse_arguments(self):
        parser = create_parser(self.program, self.usage, self.description, self.epilog)
        add_arguments(parser)

        args = parser.parse_args([self.valid_options[0], self.message, self.secret_key])
        self.assertTrue(args)
        self.assertEqual(args.option, self.valid_options[0])
        self.assertEqual(args.data, self.message)
        self.assertEqual(args.secret_key, self.secret_key)
        self.assertEqual(args.hash_algorithm, "sha256")
        self.assertEqual(args.salt_length, 8)

        args = parser.parse_args(
            [self.valid_options[1], self.sign_message, self.secret_key]
        )
        self.assertTrue(args)
        self.assertEqual(args.option, self.valid_options[1])
        self.assertEqual(args.data, self.sign_message)
        self.assertEqual(args.secret_key, self.secret_key)
        self.assertEqual(args.hash_algorithm, "sha256")
        self.assertEqual(args.salt_length, 8)

    def test_process_data(self):
        parser = create_parser(self.program, self.usage, self.description, self.epilog)
        add_arguments(parser)

        args = parser.parse_args([self.valid_options[0], self.message, self.secret_key])
        signed_data = process_data(args)

        args = parser.parse_args([self.valid_options[1], signed_data, self.secret_key])
        unsigned_data = process_data(args)

        self.assertEqual(self.message, unsigned_data)

    def test_cli(self):

        signed_data = main([self.valid_options[0], self.message, self.secret_key])

        unsigned_data = main([self.valid_options[1], signed_data, self.secret_key])
        self.assertEqual(unsigned_data, self.message)
