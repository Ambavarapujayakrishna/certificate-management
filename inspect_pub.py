import os
import pkcs11
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
    pub, priv = session.generate_keypair(
        pkcs11.KeyType.RSA,
        2048,
        label="test_probe_attrs",
        store=False,
        capabilities=pkcs11.MechanismFlag.SIGN | pkcs11.MechanismFlag.VERIFY
    )
    print("Generated keypair.")

    # Check each attribute one by one to see which ones CloudHSM supports:
    test_attrs = [
        ("CLASS", Attribute.CLASS),
        ("KEY_TYPE", Attribute.KEY_TYPE),
        ("LABEL", Attribute.LABEL),
        ("MODULUS_BITS", Attribute.MODULUS_BITS),
        ("PUBLIC_EXPONENT", Attribute.PUBLIC_EXPONENT),
        ("MODULUS", Attribute.MODULUS),
        ("VALUE", Attribute.VALUE),
        ("SUBJECT", Attribute.SUBJECT),
    ]

    for name, attr in test_attrs:
        try:
            val = pub[attr]
            val_repr = len(val) if isinstance(val, (bytes, bytearray)) else val
            print(f"  [+] {name}: SUCCESS (val={val_repr})")
        except Exception as e:
            print(f"  [-] {name}: FAILED ({e})")

    # Also test signing using session.sign
    try:
        data = b"hello test data"
        sig = session.sign(priv, data, mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS)
        print(f"  [+] session.sign SUCCESS! Sig length: {len(sig)}")
    except Exception as e:
        print(f"  [-] session.sign FAILED: {e}")

    pub.destroy()
    priv.destroy()
    print("Cleaned up.")
