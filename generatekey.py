#!/usr/bin/env python3
import json
import secrets
import argparse
from datetime import datetime, timedelta
import hashlib
import base64
import os


class KeyGenerator:
    def __init__(self):
        self.keys_base_dir = "keys"
        
    def generate_key(self, duration, unit):
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
        created_date = datetime.now()
            
        key_data = {
            "key": key,
            "created": created_date.isoformat(),
            "expires": expiration.isoformat(),
            "duration": duration,
            "unit": unit,
            "valid_days": days,
            "hash": hashlib.sha256(key.encode()).hexdigest()
        }
        
        # Store the key in date-based folder
        self._store_key(key_data, created_date)
        
        return key_data
    
    def _store_key(self, key_data, created_date):
        """Store the key in a date-based folder structure"""
        date_folder = created_date.strftime("%Y-%m-%d")
        folder_path = os.path.join(self.keys_base_dir, date_folder)
        
        # Create directory if it doesn't exist
        os.makedirs(folder_path, exist_ok=True)
        
        # Generate filename with timestamp
        timestamp = created_date.strftime("%H-%M-%S")
        filename = f"key_{timestamp}.json"
        file_path = os.path.join(folder_path, filename)
        
        # Save individual key file
        with open(file_path, 'w') as f:
            json.dump(key_data, f, indent=2)
    
    def validate_key(self, key):
        """Validate an authentication key by searching through all date folders"""
        try:
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            
            # Walk through all date folders
            for root, dirs, files in os.walk(self.keys_base_dir):
                for file in files:
                    if file.endswith('.json'):
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r') as f:
                            key_data = json.load(f)
                            
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
    
    args = parser.parse_args()
    
    generator = KeyGenerator()
    key_data = generator.generate_key(args.duration, args.unit)
    
    print("Generated Key:")
    print(key_data['key'])
    print(f"Expires: {key_data['expires']} ({args.duration} {args.unit})")


if __name__ == "__main__":
    main()
