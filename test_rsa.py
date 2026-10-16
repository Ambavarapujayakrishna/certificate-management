import os
import pkcs11
from pkcs11 import KeyType, Mechanism
from pkcs11.constants import Attribute

LIB_PATH = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"
HSM_PIN = os.getenv("CLOUDHSM_PIN", "")
if not HSM_PIN and os.path.exists(".env"):
    for line in open(".env"):
        if line.startswith("CLOUDHSM_PIN="):
            HSM_PIN = line.strip().split("=", 1)[1].strip('"').strip("'")

lib = pkcs11.lib(LIB_PATH)
token = next(lib.get_tokens())

with token.open(user_pin=HSM_PIN, rw=True) as session:
    print("Session opened.")

    # In AWS CloudHSM SDK 5, CKA_EXTRACTABLE: True on the public key is REQUIRED
    # to read CKA_MODULUS!
    pub, priv = session.generate_keypair(
        KeyType.RSA,
        2048,
        label="test_extractable",
        store=True,
        capabilities=pkcs11.MechanismFlag.SIGN | pkcs11.MechanismFlag.VERIFY,
        public_template={
            Attribute.EXTRACTABLE: True,
            Attribute.VERIFY: True,
            Attribute.ENCRYPT: True,
        },
        private_template={
            Attribute.EXTRACTABLE: False,
            Attribute.SIGN: True,
            Attribute.DECRYPT: True,
            Attribute.PRIVATE: True,
            Attribute.SENSITIVE: True,
        }
    )
    print("Keypair generated with public_template={Attribute.EXTRACTABLE: True}!")

    try:
        mod = pub[Attribute.MODULUS]
        print(f"SUCCESS: Modulus read successfully! Length: {len(mod)} bytes")
    except Exception as e:
        print("Modulus read failed:", e)

    try:
        # Also test signing
        data = b"test data"
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        print(f"SUCCESS: Signed with SHA256_RSA_PKCS! Sig length: {len(sig)} bytes")
    except Exception as e:
        print("Signing failed:", e)

    pub.destroy()
    priv.destroy()
    print("Cleanup done.")
