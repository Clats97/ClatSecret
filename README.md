# ClatSecret

**Overview**

ClatSecret Encryptext Tool v1.00 is a Python-based graphical user interface (GUI) application designed for secure text encryption and decryption using the AES-256 encryption algorithm in CBC (Cipher Block Chaining) mode. Built with Python’s tkinter library for the interface and PyCryptodome for cryptographic operations, the tool is ideal for users who require a simple yet effective means to protect textual data.


![clatsecret](https://github.com/user-attachments/assets/09e9833c-c372-45ed-8c76-53a04fbc2eb6)

________________________________________

**Features**
	**Key Management**
- Load Existing Key: Enter a 64-character hexadecimal string (representing a 32-byte key) and load it for encryption or decryption.
-	Generate New Key: Create a new random AES-256 key, which is displayed in the GUI.
-	Copy Key: Copy the generated key to your clipboard for easy use elsewhere.

	**Encryption:**
-	Plaintext Input: Enter any text you wish to encrypt.
-	Random IV Generation: Each encryption session automatically generates a unique initialization vector (IV) to ensure security.
-	AES-256 Encryption in CBC Mode: Uses AES with proper PKCS7 padding for secure encryption.
-	Base64 Encoding: The IV and ciphertext are combined and encoded in Base64, making it easy to store or transfer.
-	Copy Ciphertext: Copy the resulting Base64 ciphertext to the clipboard with a single click.

 	**Decryption:**
-	Paste Functionality: Easily paste both the AES-256 key and the Base64-encoded ciphertext from your clipboard.
-	Text Decryption: Decodes the Base64 string, separates the IV and ciphertext, and then decrypts the ciphertext to recover the original plaintext.
-	Error Handling: Provides clear error messages for invalid inputs, such as incorrect key formats or ciphertext errors.

 	**User Interface Enhancements:**
-	ASCII Branding: Displays original and additional ASCII art branding at the top of the window.
-	Informative Labels and Frames: The interface is divided into clearly defined sections for key management, encryption, and decryption.
-	Clipboard Integration: Simplifies copying and pasting keys and ciphertext to streamline the user experience.
________________________________________
**Prerequisites**
Before running the tool, ensure you have the following installed:
•	Python 3.x: You can download it from python.org.
•	PyCryptodome: Install via pip: 
pip install pycryptodome
•	tkinter: This is included with most standard Python installations. (If not, refer to your operating system’s documentation for installation instructions.)

________________________________________

**Installation and Setup**
1.	Download or Clone the Repository:
2.  Install Required Dependencies:
pip install pycryptodome
3.	Run the Application:

________________________________________
**How It Works**

**Key Management**
•	**Loading a Key:**
Enter a 64-character hexadecimal string into the “Load Key” field and click Load Key. The script converts the hex string to bytes and validates that it is exactly 32 bytes long.
•	**Generating a Key:**
Click Generate Key to create a new random 256-bit key. The key is displayed (in uppercase hex) and stored for use during encryption.
•	**Copying a Key:**
If you want to reuse the generated key elsewhere, click Copy Key to copy it to your clipboard.

**Encryption Process**

1.	**Plaintext Input:**
In the Encryption section, type the text you want to encrypt into the provided field.

2.	**Encryption Execution:**
When you click Encrypt:
-	A random 16-byte IV (Initialization Vector) is generated.
-	The plaintext is padded (using PKCS7 padding) and encrypted using AES in CBC mode.
-	The IV is concatenated with the ciphertext.
-	The combined data is then Base64 encoded and displayed in the ciphertext field.

3.	**Copying the Ciphertext:**
Click Copy Ciphertext to copy the encrypted, Base64-encoded text to your clipboard.

**Decryption Process**

4.	**Input the AES Key and Ciphertext:**
In the Decryption section:
-	Paste or enter the AES key (hex format) into the key field.
-	Paste or enter the Base64 encoded ciphertext into the ciphertext field.
-	
5.	**Decryption Execution:**
**Click Decrypt to:**
Decode the Base64 ciphertext.
-	Extract the first 16 bytes as the IV and the remainder as the actual ciphertext.
-	Decrypt the ciphertext using the provided key and IV.
-	Unpad the resulting plaintext and display it.
-	
6.	**Error Handling:**
If there are issues with the key format or ciphertext, or if decryption fails, appropriate error messages are shown.

________________________________________

**Code Structure**

•	AesEncryptionGUI Class:

The class encapsulates all GUI elements and functionalities:
- Constructor (__init__): Sets up the main window, ASCII branding, and organizes the interface into frames for key management, encryption, and decryption.
-	Key Management Methods: 
	load_key()
	generate_key()
	copy_generated_key()
-	Encryption Methods: 
	encrypt_text()
	copy_ciphertext()
-	Decryption Methods: 
	paste_key()
	paste_ciphertext()
  decrypt_text()
-	Utility Method: 
	exit_program()
•	Main Function:
Initializes the Tkinter root window and starts the event loop.

________________________________________

**Troubleshooting and Tips**
•	Key Format Errors:
Ensure that any AES key entered is exactly 64 hexadecimal characters (32 bytes).
•	Clipboard Issues:
If you encounter errors while copying or pasting, verify your system’s clipboard is accessible and that you have appropriate permissions.
•	Encryption/Decryption Mismatch:
Always use the same key for both encryption and decryption. Double-check that the correct Base64 ciphertext is being used.
•	Dependency Verification:
Confirm that all necessary libraries (tkinter and pycryptodome) are properly installed.

Copyright 2025 Joshua M Clatney (Clats97) All Rights Reserved

**DISCLAIMER: This project comes with no warranty, express or implied. The author is not responsible for abuse, misuse, or vulnerabilities. Please use responsibly and ethically in accordance with relevant laws, regulations, legislation and best practices.**
