#!/usr/bin/env python3
import json
import secrets
import argparse
from datetime import datetime, timedelta
import hashlib
import base64
import os
import uuid


class KeyGenerator:
    def __init__(self, keys_dir="keys"):
        self.keys_dir = keys_dir
        # Create directory if it doesn't exist
        os.makedirs(self.keys_dir, exist_ok=True)
        
    def generate_key(self, duration, unit, custom_filename=None):
        """Generate a new authentication key with specified validity period"""
        # Generate a cryptographically secure random key
        key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        # Calculate days based on unit
        unit_multiplier = {
            'days': 1,
            'weeks': 7,
            'months': 30,
            'years': 365
        }
        
        days = duration * unit_multiplier[unit]
        
        # Calculate expiration date
        expiration = datetime.now() + timedelta(days=days)
            
        key_data = {
            "key": key,
            "created": datetime.now().isoformat(),
            "expires": expiration.isoformat(),
            "duration": duration,
            "unit": unit,
            "valid_days": days,
            "hash": hashlib.sha256(key.encode()).hexdigest()
        }
        
        # Generate filename if not provided
        if not custom_filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            unique_id = str(uuid.uuid4())[:8]
            filename = f"key_{timestamp}_{unique_id}.json"
        else:
            filename = custom_filename
        
        # Store the key in the specified directory
        file_path = os.path.join(self.keys_dir, filename)
        self._store_key(key_data, file_path)
        
        return key_data, file_path
    
    def _store_key(self, key_data, file_path):
        """Store the key in a JSON file"""
        with open(file_path, 'w') as f:
            json.dump(key_data, f, indent=2)
    
    def validate_key(self, key):
        """Validate an authentication key by scanning all files in directory"""
        try:
            for filename in os.listdir(self.keys_dir):
                if filename.endswith('.json'):
                    file_path = os.path.join(self.keys_dir, filename)
                    with open(file_path, 'r') as f:
                        key_data = json.load(f)
                        
                    key_hash = hashlib.sha256(key.encode()).hexdigest()
                    
                    if key_data['hash'] == key_hash:
                        if datetime.fromisoformat(key_data['expires']) > datetime.now():
                            return True, key_data
                        else:
                            return False, "Key expired"
            return False, "Invalid key"
        except FileNotFoundError:
            return False, "No keys found"


def main():
    parser = argparse.ArgumentParser(description='Generate authentication keys')
    parser.add_argument('--duration', type=int, default=1, help='Duration amount')
    parser.add_argument('--unit', choices=['days', 'weeks', 'months', 'years'], default='years', help='Duration unit')
    parser.add_argument('--filename', type=str, help='Custom filename for the key (optional)')
    
    args = parser.parse_args()
    
    generator = KeyGenerator()
    key_data, file_path = generator.generate_key(args.duration, args.unit, args.filename)
    
    print("Generated Key:")
    print(key_data['key'])
    print(f"Expires: {key_data['expires']} ({args.duration} {args.unit})")
    print(f"Stored in: {file_path}")


if __name__ == "__main__":
    main()
