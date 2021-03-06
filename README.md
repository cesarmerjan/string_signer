# String Signer

This module was created to sign strings.

It's only uses building libraries, therefore, it has no external dependency.
It is also lightweight and thread-safe, which makes it ideal for use in services and microservices.

The signed string respects the following format:
    string:hash_algorithm:salt:encoded_signature


## Installation
```console
pip install String-Signer
```

## Typical usage example:

### Sign session
```python
string_signer = StringSigner("My Secret")

session_id = "b801692b-135f-40ff-8f7e-016dc7748c45"
session = {"user_uuid": "67fa3e17-4672-4036-8184-7fbe4c097439"}
encoded_session = base64.urlsafe_b64encode(json.dumps(session).encode()).decode()

signed_session = string_signer.sign(encoded_session)

redis.set(session_id, signed_session)
```

### Unsign session
```python
string_signer = StringSigner("My Secret")

session_id = "b801692b-135f-40ff-8f7e-016dc7748c45"

signed_session = redis.get(session_id)

encoded_session = string_signer.unsign(signed_session)
session = json.loads(base64.urlsafe_b64decode(encoded_session).decode())
```

### Run as module

#### Encode
```console
user@host:~$ python3 -m string_signer s 'Lorem ipsum dolor sit amet.' $SECRET_KEY
Lorem ipsum dolor sit amet.:sha256:dvL8WLar:7nVnLpJLWEgVwES2dU3vvrRwx9xr0GjNFWrsv83i2ag
```

#### Decode
```console
user@host:~$ python3 -m string_signer u 'Lorem ipsum dolor sit amet.:sha256:dvL8WLar:7nVnLpJLWEgVwES2dU3vvrRwx9xr0GjNFWrsv83i2ag' $SECRET_KEY
Lorem ipsum dolor sit amet.
```

## Test Coverage
```
Name                                      Stmts   Miss  Cover
-------------------------------------------------------------
src/__init__.py                               0      0   100%
src/string_signer/__init__.py                 4      0   100%
src/string_signer/__main__.py                29      0   100%
src/string_signer/exceptions.py              40      0   100%
src/string_signer/main.py                   135      0   100%
tests/__init__.py                             0      0   100%
tests/e2e/__init__.py                         0      0   100%
tests/e2e/test_cli.py                        23      0   100%
tests/integration/__init__.py                 0      0   100%
tests/integration/test_cli.py                48      0   100%
tests/unit/__init__.py                        0      0   100%
tests/unit/string_signer/__init__.py          0      0   100%
tests/unit/string_signer/test_signer.py     223      0   100%
-------------------------------------------------------------
TOTAL                                       502      0   100%
```