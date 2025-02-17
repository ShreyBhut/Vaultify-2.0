import os
import bcrypt
import getpass
import re
from cryptography.fernet import Fernet

class PasswordManager:
    def __init__(self, key_path='key.key', password_file='passwords.enc', master_password_file='master_password.hash'):
        self.key_path = key_path
        self.password_file = password_file
        self.master_password_file = master_password_file
        self.key = None
        self.passwords = {}
        
        self._initialize()

    def _initialize(self):
        if os.path.exists(self.key_path):
            self.load_key()
        else:
            self.create_key()
        
        if os.path.exists(self.password_file):
            self.load_passwords()

    def create_key(self):
        self.key = Fernet.generate_key()
        with open(self.key_path, 'wb') as f:
            f.write(self.key)

    def load_key(self):
        with open(self.key_path, 'rb') as f:
            self.key = f.read()

    def encrypt(self, data):
        cipher = Fernet(self.key)
        return cipher.encrypt(data.encode()).decode()

    def decrypt(self, data):
        cipher = Fernet(self.key)
        return cipher.decrypt(data.encode()).decode()

    def is_valid_password(self, password):
        return (len(password) > 8 and
                re.search(r"[!@#$%^&*]", password) and
                re.search(r"[A-Z]", password) and
                re.search(r"[a-z]", password) and
                re.search(r"\d", password))

    def set_master_password(self):
        while True:
            password = getpass.getpass("Create a master password: ")
            if not self.is_valid_password(password):
                print("Password must be at least 9 characters long")
                print("contain at least one special character (!@#$%^&*)") 
                print("have both uppercase and lowercase letters") 
                print("have both uppercase and lowercase letters, and include at least one number.")
                continue
            confirm_password = getpass.getpass("Re-enter master password: ")
            if password != confirm_password:
                print("Passwords do not match. Try again.")
                continue
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            with open(self.master_password_file, 'wb') as f:
                f.write(hashed)
            print("Master password set successfully!")
            break

    def verify_master_password(self, password):
        if not os.path.exists(self.master_password_file):
            return False
        with open(self.master_password_file, 'rb') as f:
            stored_hash = f.read()
        return bcrypt.checkpw(password.encode(), stored_hash)

    def load_passwords(self):
        with open(self.password_file, 'r') as f:
            for line in f:
                site, enc_pass = line.strip().split(':', 1)
                self.passwords[site] = self.decrypt(enc_pass)

    def save_passwords(self):
        with open(self.password_file, 'w') as f:
            for site, password in self.passwords.items():
                f.write(f"{site}:{self.encrypt(password)}\n")

    def add_password(self, site, password):
        if not self.is_valid_password(password):
            print("Password must be at least 9 characters long")
            print("Contain at least one special character (!@#$%^&*)") 
            print("Have both uppercase and lowercase letters") 
            print("Include at least one number.")
            return
        self.passwords[site] = password
        self.save_passwords()
        print("Password saved successfully!")

    def get_password(self, site):
        return self.passwords.get(site, "Password not found.")

    def delete_password(self, site):
        if site in self.passwords:
            del self.passwords[site]
            self.save_passwords()
            return True
        return False

    def update_password(self, site, new_password):
        if not self.is_valid_password(new_password):
            print("Password does not meet security requirements!")
            return False
        if site in self.passwords:
            self.passwords[site] = new_password
            self.save_passwords()
            return True
        return False

def main():
    pm = PasswordManager()
    
    if not os.path.exists(pm.master_password_file):
        print("Set up a master password for first-time use.")
        pm.set_master_password()
    
    master_password = getpass.getpass("Enter master password: ")
    if not pm.verify_master_password(master_password):
        print("Incorrect master password!")
        return
    
    while True:
        print("\nPassword Manager CLI")
        print("1. Add a new password")
        print("2. Retrieve a password")
        print("3. Update a password")
        print("4. Delete a password")
        print("5. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == '1':
            site = input("Enter site name: ")
            password = getpass.getpass("Enter password: ")
            pm.add_password(site, password)
        elif choice == '2':
            site = input("Enter site name: ")
            print("Password:", pm.get_password(site))
        elif choice == '3':
            site = input("Enter site name: ")
            new_password = getpass.getpass("Enter new password: ")
            if pm.update_password(site, new_password):
                print("Password updated successfully!")
            else:
                print("Site not found!")
        elif choice == '4':
            site = input("Enter site name: ")
            if pm.delete_password(site):
                print("Password deleted successfully!")
            else:
                print("Site not found!")
        elif choice == '5':
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == '__main__':
    main()
