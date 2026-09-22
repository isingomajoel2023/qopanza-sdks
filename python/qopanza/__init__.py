"""Post-quantum cryptography as an API call.

    from qopanza import QopanzaClient

    with QopanzaClient() as client:
        account = client.signup("you@example.com", "a-real-password")
        print(account["api_key"])   # shown once — store it now

Talks to https://api.qopanza.com by default. Pass `base_url` (or set
QOPANZA_BASE_URL for the CLI) to reach a backend you run yourself.

`zk` (zero-knowledge mode: keys generated and used on your own machine)
is deliberately NOT imported here — it needs the optional native
dependency from the `zk` extra, and importing it eagerly would make a
plain `pip install qopanza` fail at import time. Reach for it
explicitly: `from qopanza import zk`.
"""

from qopanza.client import QopanzaAPIError, QopanzaClient

# QopanzaAPIError is exported because catching it is not optional in
# real use — every method raises it on any 4xx/5xx, and requiring a
# submodule import to write `except` is a papercut on the first thing a
# new user does after the happy path.
__all__ = ["QopanzaAPIError", "QopanzaClient"]
__version__ = "0.2.0"
