import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import main as gateway_main
from v3 import app

# Public verification material only. The matching private signing key is stored
# only in the DAHCorp Netlify runtime. Keeping the rotation in this thin module
# lets every existing v1/v2/v3 route use the new key without changing the
# gateway's route contracts.
_ROTATED_DAHCORP_PUBLIC_KEY_B64 = "MCowBQYDK2VwAyEAk35jhO+U3Puj6mFmNLUHftsaXpK1JrnsRqPqyhP7DEM="

_rotated_key = serialization.load_der_public_key(base64.b64decode(_ROTATED_DAHCORP_PUBLIC_KEY_B64))
if not isinstance(_rotated_key, Ed25519PublicKey):
    raise RuntimeError("Rotated DAHCorp gateway verification key is not Ed25519.")

gateway_main._public_key = _rotated_key
