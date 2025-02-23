import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import numpy as np
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

class DecryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography Decoder")
        self.root.geometry("500x400")
        
        # Image selection
        tk.Label(self.root, text="Step 1: Select Encrypted Image", font=('Arial', 10, 'bold')).pack(pady=5)
        self.image_btn = tk.Button(self.root, text="Choose Image", command=self.choose_image)
        self.image_btn.pack()
        
        # Password input
        tk.Label(self.root, text="Step 2: Enter Password", font=('Arial', 10, 'bold')).pack(pady=5)
        self.password_entry = tk.Entry(self.root, show="*", width=30)
        self.password_entry.pack()
        
        # Decrypt button
        tk.Label(self.root, text="Step 3: Decrypt Message", font=('Arial', 10, 'bold')).pack(pady=5)
        self.decrypt_btn = tk.Button(self.root, text="Decrypt Message", command=self.decrypt_message)
        self.decrypt_btn.pack(pady=10)
        
        # Message output
        tk.Label(self.root, text="Decrypted Message:", font=('Arial', 10, 'bold')).pack(pady=5)
        self.message_text = tk.Text(self.root, height=5, width=30)
        self.message_text.pack()
        
        # Status
        self.status_label = tk.Label(self.root, text="")
        self.status_label.pack(pady=10)
        
        self.image_path = None
        
    def choose_image(self):
        self.image_path = filedialog.askopenfilename(
            filetypes=[("PNG Files", "*.png")]
        )
        if self.image_path:
            self.status_label.config(text=f"Selected: {os.path.basename(self.image_path)}")
            
    def get_encryption_key(self, password):
        salt = b'salt_123'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def extract_bit(self, pixel):
        return pixel & 1
        
    def decrypt_message(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image first!")
            return
            
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter password!")
            return
            
        try:
            # Load image
            img = Image.open(self.image_path)
            img_array = np.array(img)
            
            # Extract length first (32 bits)
            length_binary = ''
            idx = 0
            for i in range(32):
                x = (idx // img_array.shape[1]) % img_array.shape[0]
                y = idx % img_array.shape[1]
                c = idx // (img_array.shape[0] * img_array.shape[1])
                length_binary += str(self.extract_bit(img_array[x, y, c % 3]))
                idx += 1
            
            message_length = int(length_binary, 2)
            
            # Extract message bits
            binary_message = ''
            for i in range(message_length):
                x = (idx // img_array.shape[1]) % img_array.shape[0]
                y = idx % img_array.shape[1]
                c = idx // (img_array.shape[0] * img_array.shape[1])
                binary_message += str(self.extract_bit(img_array[x, y, c % 3]))
                idx += 1
            
            # Convert binary to bytes
            message_bytes = bytes(
                int(binary_message[i:i+8], 2) for i in range(0, len(binary_message), 8)
            )
            
            # Decrypt message
            key = self.get_encryption_key(password)
            f = Fernet(key)
            decrypted_message = f.decrypt(message_bytes).decode()
            
            # Show decrypted message
            self.message_text.delete("1.0", tk.END)
            self.message_text.insert("1.0", decrypted_message)
            messagebox.showinfo("Success", "Message decrypted successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = DecryptApp(root)
    root.mainloop()