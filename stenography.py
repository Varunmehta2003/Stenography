import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image
import numpy as np
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography")
        self.root.geometry("600x400")
        self.setup_gui()
        
    def setup_gui(self):
        # Image selection
        tk.Label(self.root, text="Select Image:").pack(pady=10)
        self.image_btn = tk.Button(self.root, text="Choose Image", command=self.choose_image)
        self.image_btn.pack()
        
        # Message input
        tk.Label(self.root, text="Secret Message:").pack(pady=10)
        self.message_text = tk.Text(self.root, height=4, width=50)
        self.message_text.pack()
        
        # Password input
        tk.Label(self.root, text="Password:").pack(pady=10)
        self.password_entry = tk.Entry(self.root, show="*", width=30)
        self.password_entry.pack()
        
        # Action buttons
        self.encrypt_btn = tk.Button(self.root, text="Encrypt Message", command=self.encrypt_message)
        self.encrypt_btn.pack(pady=10)
        
        self.decrypt_btn = tk.Button(self.root, text="Decrypt Message", command=self.decrypt_message)
        self.decrypt_btn.pack(pady=10)
        
        # Status
        self.status_label = tk.Label(self.root, text="")
        self.status_label.pack(pady=10)
        
        self.image_path = None
        
    def choose_image(self):
        self.image_path = filedialog.askopenfilename(
            filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp")]
        )
        if self.image_path:
            self.status_label.config(text=f"Selected: {os.path.basename(self.image_path)}")
            
    def get_encryption_key(self, password):
        """Generate encryption key from password"""
        salt = b'salt_123'  # In production, use a random salt and store it
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def embed_bit(self, pixel, bit):
        """Embed a single bit into a pixel value"""
        # Clear the least significant bit and add our bit
        return (pixel & 0xFE) | bit
    
    def extract_bit(self, pixel):
        """Extract the least significant bit from a pixel value"""
        return pixel & 1
    
    def encrypt_message(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image first!")
            return
            
        message = self.message_text.get("1.0", tk.END).strip()
        password = self.password_entry.get()
        
        if not message or not password:
            messagebox.showerror("Error", "Please enter both message and password!")
            return
            
        try:
            # Load and convert image to numpy array
            img = Image.open(self.image_path)
            img_array = np.array(img, dtype=np.uint8)
            
            # Encrypt message
            key = self.get_encryption_key(password)
            f = Fernet(key)
            encrypted_message = f.encrypt(message.encode())
            
            # Convert encrypted message to binary
            binary_message = ''.join(format(byte, '08b') for byte in encrypted_message)
            
            if len(binary_message) > img_array.size:
                messagebox.showerror("Error", "Message too long for this image!")
                return
            
            # Embed message length at the start
            length_binary = format(len(binary_message), '032b')
            
            # Create a copy of the image array
            modified_array = img_array.copy()
            idx = 0
            
            # First embed length
            for i in range(32):
                x = (idx // img_array.shape[1]) % img_array.shape[0]
                y = idx % img_array.shape[1]
                c = idx // (img_array.shape[0] * img_array.shape[1])
                modified_array[x, y, c % 3] = self.embed_bit(modified_array[x, y, c % 3], int(length_binary[i]))
                idx += 1
            
            # Then embed message
            for bit in binary_message:
                x = (idx // img_array.shape[1]) % img_array.shape[0]
                y = idx % img_array.shape[1]
                c = idx // (img_array.shape[0] * img_array.shape[1])
                modified_array[x, y, c % 3] = self.embed_bit(modified_array[x, y, c % 3], int(bit))
                idx += 1
            
            # Save modified image
            output_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG files", "*.png")]
            )
            if output_path:
                Image.fromarray(modified_array).save(output_path)
                messagebox.showinfo("Success", "Message encrypted successfully!")
                
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
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
            
            # Convert binary message to bytes
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
    app = SteganographyApp(root)
    root.mainloop()