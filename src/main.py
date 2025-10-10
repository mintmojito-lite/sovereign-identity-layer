import sys
import os
import time
import secrets
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from user_device import SDILWallet
from instagram_server import InstagramServer

def simulate_sdi_l_login(user_id="user123"):
    print(f"=== SDI-L Login Simulation for {user_id} (Persistent DB) ===")
    
    print("Step 1: User clicks 'Login with SDI-L' on Instagram.")
    
    server = InstagramServer()  # Loads from DB
    existing_devices = server.get_registered_devices(user_id)
    wallet = SDILWallet()
    
    if not existing_devices:
        print("No existing devices – registering new one.")
        wallet.generate_keys()
        server.register_device(user_id, wallet.public_ver_key)
    else:
        print(f"Existing devices found: {existing_devices}")
        # Sync wallet to existing key for proof match
        existing_pub_key = server.user_devices[user_id][0]['public_ver_key']
        wallet.public_ver_key = existing_pub_key
        wallet.master_key = existing_pub_key  # Sync for mock proof
        print(f"Using existing device key for proof simulation: {existing_pub_key}")
    
    challenge = server.generate_challenge(user_id)
    
    print("Step 3-4: Device unlocks (biometric) and generates ZKP proof.")
    try:
        secret = wallet.biometric_unlock()  # PIN: 1234
        proof = wallet.generate_zkp_proof(challenge)
    except ValueError as e:
        print(f"Flow failed: {e}")
        return False, None, server
    
    print("Step 5: ZKP Proof sent to Instagram server.")
    
    print("Step 6: Server verifies proof with public key (incl. TTL check).")
    verified, token = server.verify_zkp_proof(user_id, challenge, proof)
    
    if verified:
        print("Step 7: Access granted – Session token issued!")
        print(f"Received Token: {token}")
        return True, token, server
    else:
        print("Step 7: Access denied!")
        return False, None, server

def simulate_persistence_demo(user_id="user123"):
    print(f"\n=== Persistence Demo for {user_id} ===")
    
    server = InstagramServer()  # Reloads from DB
    print(f"Loaded devices: {server.get_registered_devices(user_id)}")
    print(f"Loaded sessions: {len(server.active_sessions)} active")
    
    if server.get_registered_devices(user_id):
        if user_id in server.active_sessions:
            token = server.active_sessions[user_id]
            valid = server.validate_session(user_id, token)
            print(f"Existing Session Validation: {'Success!' if valid else 'Failed!'}")
        else:
            print("No existing session – would need re-login.")
    else:
        print("No data yet – run login first!")
    
    if user_id in server.active_sessions:
        server.revoke_session(user_id)
        print("Demo Revocation: Applied (persists to DB).")

if __name__ == "__main__":
    success, token, server = simulate_sdi_l_login()
    print(f"\nNormal Login {'Success!' if success else 'Failed!'}")
    
    if success:
        print("\n--- Revocation (Persists) ---")
        revoked = server.revoke_session("user123")
        print(f"Revocation: {'Success!' if revoked else 'Failed!'}")
    
    simulate_persistence_demo()