# Image Steganography Project

This project provides two Python applications for hiding secret messages within images (steganography) using password protection. The project is split into two separate applications: one for encrypting messages into images and another for decrypting messages from images.

## Features

- GUI-based interface for easy usage
- Password-protected message encryption
- Support for PNG, JPG, and BMP image formats
- Secure encryption using Fernet (symmetric encryption)
- Minimal visual impact on the carrier image
- Separate programs for encryption and decryption

## Requirements

- Python 3.x
- Required Python packages:
  ```
  pip install pillow numpy cryptography
  ```

## Installation

1. Clone or download this repository
2. Install the required packages:
   ```bash
   pip install pillow numpy cryptography
   ```
3. Save the two Python files (`encrypt.py` and `decrypt.py`) to your preferred location

## Usage

### Encryption (encrypt.py)

1. Run the encryption program:
   ```bash
   python encrypt.py
   ```
2. Follow the steps in the GUI:
   - Step 1: Click "Choose Image" to select your carrier image
   - Step 2: Enter your secret message in the text box
   - Step 3: Enter a password (remember this for decryption)
   - Step 4: Click "Encrypt Message" and choose where to save the encrypted image

### Decryption (decrypt.py)

1. Run the decryption program:
   ```bash
   python decrypt.py
   ```
2. Follow the steps in the GUI:
   - Step 1: Click "Choose Image" to select the encrypted image
   - Step 2: Enter the password used during encryption
   - Step 3: Click "Decrypt Message" to reveal the hidden message

## Technical Details

- The program uses the least significant bit (LSB) technique for steganography
- Messages are encrypted using Fernet symmetric encryption before embedding
- Password-based key derivation uses PBKDF2HMAC with SHA256
- The encrypted message length is embedded at the start of the image
- Images with hidden messages are saved in PNG format to prevent data loss

## Limitations

- The carrier image must be large enough to hold the encrypted message
- Only supports text messages (no file embedding)
- Encrypted images must be saved as PNG to preserve the hidden message
- The original image proportions must be maintained to decrypt successfully

## Security Considerations

- Always use strong passwords
- Keep your encrypted images secure
- Don't share the password through the same channel as the encrypted image
- The program uses a fixed salt for key derivation (can be modified for production use)

## Error Messages

- "Please select an image first!" - No image was selected
- "Please enter both message and password!" - Missing message or password
- "Message too long for this image!" - Choose a larger image or shorter message
- "Encryption/Decryption failed" - Various causes, check password and image integrity

## Files

- `encrypt.py` - The encryption program
- `decrypt.py` - The decryption program
- `README.md` - This documentation file

