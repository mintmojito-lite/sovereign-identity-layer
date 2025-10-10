from flask import Flask, request, jsonify
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from instagram_server import InstagramServer

app = Flask(__name__)
server = InstagramServer()

@app.route('/register_device', methods=['POST'])
def register_device():
    data = request.json
    user_id = data.get('user_id')
    public_ver_key_str = data.get('public_ver_key')
    if not user_id or not public_ver_key_str:
        return jsonify({'error': 'Missing user_id or public_ver_key (str)'}), 400
    try:
        public_ver_key = int(public_ver_key_str)
        server.register_device(user_id, public_ver_key)
        return jsonify({'message': 'Device registered', 'devices': server.get_registered_devices(user_id)}), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/generate_challenge', methods=['POST'])
def generate_challenge():
    data = request.json
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'error': 'Missing user_id'}), 400
    try:
        challenge = server.generate_challenge(user_id)
        return jsonify({'challenge': challenge, 'issued_at': server.challenge_timestamps.get(user_id, 0)}), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/verify_proof', methods=['POST'])
def verify_proof():
    data = request.json
    user_id = data.get('user_id')
    challenge = data.get('challenge')
    proof = data.get('proof')
    if not all([user_id, challenge, proof]):
        return jsonify({'error': 'Missing user_id, challenge, or proof'}), 400
    try:
        verified, token = server.verify_zkp_proof(user_id, int(challenge), int(proof))
        if verified:
            return jsonify({'verified': True, 'token': token}), 200
        else:
            return jsonify({'verified': False, 'error': 'Invalid proof or TTL exceeded'}), 401
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

@app.route('/validate_session', methods=['POST'])
def validate_session():
    data = request.json
    user_id = data.get('user_id')
    token = data.get('token')
    if not user_id or not token:
        return jsonify({'error': 'Missing user_id or token'}), 400
    valid = server.validate_session(user_id, token)
    return jsonify({'valid': valid}), 200

@app.route('/revoke_session', methods=['POST'])
def revoke_session():
    data = request.json
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'error': 'Missing user_id'}), 400
    revoked = server.revoke_session(user_id)
    return jsonify({'revoked': revoked}), 200

@app.route('/devices/<user_id>', methods=['GET'])
def get_devices(user_id):
    devices = server.get_registered_devices(user_id)
    return jsonify({'user_id': user_id, 'devices': devices}), 200

if __name__ == '__main__':
    print("SDI-L API Server starting on http://localhost:5000")
    print("Test with curl, e.g., POST /register_device with JSON body.")
    app.run(debug=True, host='0.0.0.0', port=5000)