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

print(f"Using PIN: {HSM_PIN[:4]}****")

lib = pkcs11.lib(LIB_PATH)
token = next(lib.get_tokens())
print(f"Token: {token.label}")

with token.open(user_pin=HSM_PIN) as session:
    print("Session opened and logged in.")
    print("Generating RSA key pair (2048-bit)...")

    pub, priv = session.generate_keypair(
        KeyType.RSA,
        2048,
        label="test_py_rsa",
        store=True,
        capabilities=pkcs11.MechanismFlag.SIGN | pkcs11.MechanismFlag.VERIFY
    )
    print("RSA Key pair generated!")
    print(f"Public key handle: {pub}")
    print(f"Private key handle: {priv}")

    # Read modulus
    modulus = pub[Attribute.MODULUS]
    print(f"SUCCESS: Modulus retrieved, length: {len(modulus)} bytes")

    # Sign data
    data = b"hello world from python"
    sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
    print(f"SUCCESS: Signed with SHA256_RSA_PKCS, sig length: {len(sig)} bytes")

    # Cleanup
    pub.destroy()
    priv.destroy()
    print("Test keys destroyed.")
