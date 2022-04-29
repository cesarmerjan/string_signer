import argparse
import sys
from typing import List

from .main import StringSigner

PROGRAM = "StringSigner"
USAGE = "python -m string_signer [ s | u ] 'my data' $SECRET_KEY"
DESCRIPTION = """
------------------------------------------------------------------------------

Description:

Use this module to sign strings.

The signed string respects the following format:
    string:hash_algorithm:salt:encoded_signature

------------------------------------------------------------------------------

Arguments:

"""
EPILOG = "Copyrights @CesarMerjan"


def create_parser(
    prog: str, usage: str, descrption: str, epilog: str
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        usage=usage,
        description=descrption,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )
    return parser


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "option",
        type=str,
        choices=("s", "u"),
        metavar="option",
        help="use 's' to sign data and 'u' to unsign data",
    )

    parser.add_argument(
        "data",
        type=str,
        metavar="data",
        help="the data in string format to be signed or unsigned",
    )

    parser.add_argument(
        "secret_key",
        type=str,
        metavar="secret_key",
        help="secret key used to sign and unsign data",
    )

    parser.add_argument(
        "-l",
        "--salt_length",
        type=int,
        metavar="salt_length",
        default=8,
        help="salt length used to sign data. Default is 8",
    )

    parser.add_argument(
        "-a",
        "--hash_algorithm",
        type=str,
        metavar="hash_algorithm",
        default="sha256",
        help="hash algorithm used to sign data. Default is sha256",
    )


def process_data(args: argparse.Namespace) -> str:

    string_signer = StringSigner(
        secret_key=args.secret_key,
        hash_algorithm=args.hash_algorithm,
        salt_length=args.salt_length,
    )

    if args.option == "s":
        result = string_signer.sign(args.data)
    else:
        result = string_signer.unsign(args.data)

    return result


def main(argv: List[str] = None) -> str:
    parser = create_parser(PROGRAM, USAGE, DESCRIPTION, EPILOG)
    add_arguments(parser)
    args = parser.parse_args(argv)
    result = process_data(args)
    return result


if __name__ == "__main__":  # pragma: no cover
    if len(sys.argv) <= 1:
        sys.argv.append("--help")

    print(main())

    sys.exit()
