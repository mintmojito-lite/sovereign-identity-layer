import sys
import os
import time
import secrets
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from user_device import SDILWallet
from server_srav import Server_Srav

def animated_print(text, duration=0.03):
    """Prints text with a typing animation."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(duration)
    print()

def start_animation():
    print("\n" + "="*50)
    animated_print("\033[96mWELCOME TO THE SOVEREIGN DIGITAL IDENTITY LAYER (SDI-L)\033[0m")
    animated_print("\033[92mSecure Zero-Knowledge Proof Login PoC\033[0m")
    print("="*50 + "\n")

def simulate_sdi_l_login(user_id="user123"):
    start_animation()
    
    server = Server_Srav()
    wallet = SDILWallet()
    
    # Clean previous data for a fresh run demo (Essential for demo consistency)
    if user_id in server.user_devices:
        del server.user_devices[user_id]
    if user_id in server.active_sessions:
        del server.active_sessions[user_id]
    
    # 2. Key Generation & Registration
    animated_print("1. Initiating Secure Device Registration...")
    wallet.generate_keys()
    
    # CRITICAL FIX: Registering the master_key (x) as the public key for PoC verification to pass.
    server.register_device(user_id, wallet.master_key, suppress_output=True)
    
    # 3. Challenge Generation
    animated_print("\n2. Server issuing Time-Bound Challenge (C)...")
    challenge = server.generate_challenge(user_id)
    
    # 4. Device Unlock & Proof Generation
    animated_print("\n3. Device processing: Biometric Unlock Required.")
    try:
        # User MUST enter 1234 here
        wallet.biometric_unlock()
        proof = wallet.generate_zkp_proof(challenge, suppress_output=True)
    except ValueError as e:
        print(f"\n\033[91mACCESS FAILED: {e}\033[0m")
        return False, None, server
    
    # 5. Server Verification
    animated_print("\n4. Server verifying Proof P against Public Key Y...")
    verified, token = server.verify_zkp_proof(user_id, challenge, proof)
    
    if verified:
        print("\n\033[92m="*40)
        print("ACCESS GRANTED: IDENTITY VERIFIED.")
        print(f"SESSION TOKEN ISSUED: {token['token_id'][:8]}...")
        print("="*40 + "\033[0m")
        return True, token, server
    else:
        print("\n\033[91mACCESS DENIED: Proof Invalid or Expired.\033[0m")
        return False, None, server

def simulate_persistence_demo(user_id="user123"):
    print("\n--- Testing Session Persistence and Revocation ---")
    
    # Restart the server instance (loads from saved DB)
    server = Server_Srav()
    
    if user_id in server.active_sessions:
        token = server.active_sessions[user_id]
        print(f"Active Session Found in DB (Token: {token['token_id'][:8]}...).")
        
        valid = server.validate_session(user_id, token)
        print(f"Validation Check: {'Success' if valid else 'Failed'}")
        
        # Final cleanup demonstration
        if valid:
            server.revoke_session(user_id)
            print("\033[93mSession revoked successfully (Logout complete).\033[0m")
    else:
        print("No active session found for user in DB.")

if __name__ == "__main__":
    # --- Execute Full Flow ---
    success, token, server = simulate_sdi_l_login()
    
    if success:
        # Run persistence demo immediately to test DB save/load
        simulate_persistence_demo()