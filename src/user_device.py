import getpass
from cryptography.hazmat.primitives.asymmetric import ec
import secrets

class SDILWallet:
    def __init__(self):
        self.master_key = None
        self.public_ver_key = None

    def generate_keys(self):
        private_key = ec.generate_private_key(ec.SECP384R1())
        self.master_key = private_key.private_numbers().private_value
        public_key = private_key.public_key()
        self.public_ver_key = self.master_key  # Mock for sim
        print("Keys generated – Master key local, public ready for server.")

    def biometric_unlock(self):
        pin = getpass.getpass("Enter PIN for biometric unlock: ")
        if pin == "1234":
            if self.master_key is None:
                raise ValueError("Generate keys first!")
            print("Biometric unlock success – Master key accessed.")
            return self.master_key
        else:
            raise ValueError("Biometric/PIN failed – Access denied.")

    def generate_zkp_proof(self, challenge):
        if self.master_key is None:
            raise ValueError("Unlock wallet first!")
        p = 2**256 - 189
        proof = pow(challenge, self.master_key, p)
        print(f"ZKP Proof generated for challenge {challenge}: {proof} (secret hidden).")
        return proof

if __name__ == "__main__":
    wallet = SDILWallet()
    wallet.generate_keys()
    try:
        secret = wallet.biometric_unlock()
        challenge = 12345
        proof = wallet.generate_zkp_proof(challenge)
        print(f"Proof: {proof}")
    except ValueError as e:
        print(f"Error: {e}")