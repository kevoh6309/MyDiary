import os
import json
from datetime import datetime
from getpass import getpass
import base64
from hashlib import sha256
import sys

class EncryptedDiary:
    def __init__(self):
        self.diary_file = "diary_data.enc"
        self.key_file = "diary_key.key"
        self.fernet = None
        self.entries = []
        
    def generate_key(self, password):
        """Generate encryption key from password"""
        # Use SHA-256 to derive a consistent key from the password
        digest = sha256(password.encode()).digest()
        # Convert to URL-safe base64 for Fernet
        return base64.urlsafe_b64encode(digest)
    
    def initialize_fernet(self, password):
        """Initialize Fernet with the password-derived key"""
        key = self.generate_key(password)
        self.fernet = Fernet(key)
    
    def encrypt_data(self, data):
        """Encrypt string data"""
        if not self.fernet:
            raise ValueError("Fernet not initialized")
        return self.fernet.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data):
        """Decrypt string data"""
        if not self.fernet:
            raise ValueError("Fernet not initialized")
        return self.fernet.decrypt(encrypted_data.encode()).decode()
    
    def load_data(self):
        """Load and decrypt diary data"""
        if not os.path.exists(self.diary_file):
            return []
            
        try:
            with open(self.diary_file, 'r') as f:
                encrypted_data = f.read()
                if not encrypted_data:
                    return []
                
                decrypted_data = self.decrypt_data(encrypted_data)
                return json.loads(decrypted_data)
        except (json.JSONDecodeError, ValueError) as e:
            print(f"Error decrypting/loading data: {e}")
            return []
    
    def save_data(self):
        """Encrypt and save diary data"""
        data_to_save = json.dumps(self.entries)
        encrypted_data = self.encrypt_data(data_to_save)
        
        with open(self.diary_file, 'w') as f:
            f.write(encrypted_data)
    
    def add_entry(self):
        """Add a new diary entry"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print("\nNew Diary Entry (Press Ctrl+D on empty line to finish):")
        print(f"Date: {timestamp}")
        
        content = []
        while True:
         try:
            while True:
                line = input()
                content.append(line)
         except EOFError:
            pass  # Ctrl+D pressed
        
        entry = {
            'timestamp': timestamp,
            'content': '\n'.join(content)
        }
        self.entries.append(entry)
        self.save_data()
        print("\nEntry saved successfully!")
    
    def view_entries(self):
        """View all diary entries"""
        if not self.entries:
            print("\nNo entries found.")
            return
            
        print("\nDiary Entries:")
        for i, entry in enumerate(self.entries, 1):
            print(f"\nEntry {i}:")
            print(f"Date: {entry['timestamp']}")
            print("Content:")
            print(entry['content'])
            print("-" * 40)
    
    def delete_entry(self, index):
        """Delete a diary entry by index"""
        try:
            if 1 <= index <= len(self.entries):
                deleted = self.entries.pop(index - 1)
                self.save_data()
                print(f"\nDeleted entry from {deleted['timestamp']}")
            else:
                print("\nInvalid entry number.")
        except IndexError:
            print("\nInvalid entry number.")
    
    def search_entries(self, keyword):
        """Search entries containing a keyword"""
        found = []
        keyword = keyword.lower()
        for entry in self.entries:
            if keyword in entry['content'].lower():
                found.append(entry)
        
        if not found:
            print("\nNo entries found containing that keyword.")
            return
            
        print(f"\nFound {len(found)} entries containing '{keyword}':")
        for i, entry in enumerate(found, 1):
            print(f"\nEntry {i}:")
            print(f"Date: {entry['timestamp']}")
            print("Content:")
            print(entry['content'][:200] + ("..." if len(entry['content']) > 200 else ""))
            print("-" * 40)
    
    def run(self):
        """Main application loop"""
        print("Welcome to your Encrypted Diary!")
        
        # Check if this is first run
        first_run = not os.path.exists(self.diary_file)
        
        if first_run:
            print("\nThis appears to be your first time using the diary.")
            print("You'll need to set a password to encrypt your diary.")
            password = input("Choose a strong password: ")
            confirm = input("Confirm password: ")
            
            if password != confirm:
                print("Passwords don't match. Exiting.")
                sys.exit(1)
                
            self.initialize_fernet(password)
            print("\nDiary initialized successfully!")
        else:
            password = getpass("Enter your diary password: ")
            self.initialize_fernet(password)
            
            # Test decryption
            try:
                self.entries = self.load_data()
            except:
                print("Incorrect password or corrupted diary file.")
                sys.exit(1)
        
        while True:
            print("\nMenu:")
            print("1. Add new entry")
            print("2. View all entries")
            print("3. Search entries")
            print("4. Delete entry")
            print("5. Exit")
            
            choice = input("Enter your choice (1-5): ")
            
            if choice == "1":
                self.add_entry()
            elif choice == "2":
                self.view_entries()
            elif choice == "3":
                keyword = input("Enter search keyword: ")
                self.search_entries(keyword)
            elif choice == "4":
                try:
                    index = int(input("Enter entry number to delete: "))
                    self.delete_entry(index)
                except ValueError:
                    print("Please enter a valid number.")
            elif choice == "5":
                print("Goodbye!")
                break
            else:
                print("Invalid choice. Please enter 1-5.")

if __name__ == "__main__":
    diary = EncryptedDiary()
    diary.run()