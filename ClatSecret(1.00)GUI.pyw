import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

class AesEncryptionGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("ClatSecret Encryptext Tool v1.00")
        self.encryption_key = None  # Stores key used for encryption only

        self.generated_key_var = tk.StringVar()
        self.encrypted_var = tk.StringVar()

        # ---- ASCII Branding ----
        branding_frame = tk.Frame(master)
        branding_frame.pack(anchor="w")

        # Original ASCII art (ClatSecret Branding)
        ascii_art_red = (
            " ██████╗██╗      █████╗ ████████╗\n"
            " ██╔════╝██║     ██╔══██╗╚══██╔══╝\n"
            " ██║     ██║     ███████║   ██║\n"
            " ██║     ██║     ██╔══██║   ██║\n"
            " ╚██████╗███████╗██║  ██║   ██║\n"
            "  ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝  \n\n"
            " ███████╗███████╗ ██████╗██████╗ ███████╗████████╗\n"
            " ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝\n"
            " ███████╗█████╗  ██║     ██████╔╝█████╗     ██║\n"
            " ╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║\n"
            " ███████║███████╗╚██████╗██║  ██║███████╗   ██║\n"
            " ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝\n"
        )
        ascii_art_red_label = tk.Label(
            branding_frame,
            text=ascii_art_red,
            justify="left",
            font=("Courier", 10)
        )
        ascii_art_red_label.pack(side="left")

        # New ASCII art to be placed beside the ClatSecret branding
        new_ascii_art = (
            "       ########      \n"
            "    ############    \n"
            "    ###      ####   \n"
            "    ###      ####   \n"
            "  ################  \n"
            "  ################  \n"
            "  ######=  =######  \n"
            "  #######..*######  \n"
            "  ######*  +######  \n"
            "  ######****######  \n"
            "  ################  \n"
        )
        new_ascii_label = tk.Label(
            branding_frame,
            text=new_ascii_art,
            justify="left",
            font=("Courier", 10)
        )
        new_ascii_label.pack(side="left", padx=(10, 0))  # Add a little space between the two arts

        tk.Label(
            master,
            text="C L A T S E C R E T   E N C R Y P T E X T   T O O L (Version 1.00)",
            fg="blue",
            font=("Arial", 12, "bold")
        ).pack()

        # Center the following informational text
        tk.Label(
            master,
            text="By Joshua Clatney - Ethical Pentesting Enthusiast\n[Text Encrypter]\nFrom Plain To Protected And Back Again",
            justify="center"
        ).pack(anchor="center")

        # ---- Frame for encryption key controls ----
        key_frame = tk.LabelFrame(master, text="Encryption Key")
        key_frame.pack(fill="both", expand="yes", padx=10, pady=5)

        tk.Label(key_frame, text="Load Key:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.load_key_entry = tk.Entry(key_frame, width=70)
        self.load_key_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(key_frame, text="Load Key", command=self.load_key).grid(row=0, column=2, padx=5, pady=5)
        # Changed button text from "Generate New Key" to "Generate Key"
        tk.Button(key_frame, text="Generate Key", command=self.generate_key).grid(row=0, column=3, padx=5, pady=5)

        tk.Label(key_frame, text="Generated Key:").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        self.generated_key_entry = tk.Entry(key_frame, textvariable=self.generated_key_var, width=70, state="readonly")
        self.generated_key_entry.grid(row=2, column=1, padx=5, pady=5)
        tk.Button(key_frame, text="Copy Key", command=self.copy_generated_key).grid(row=2, column=2, padx=5, pady=5)

        # ---- Frame for encryption ----
        encrypt_frame = tk.LabelFrame(master, text="Encryption")
        encrypt_frame.pack(fill="both", expand="yes", padx=10, pady=5)

        # Plaintext label and entry with the Encrypt button placed beside the entry.
        tk.Label(encrypt_frame, text="Plaintext to Encrypt:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.encrypt_text_entry = tk.Entry(encrypt_frame, width=70)
        self.encrypt_text_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(encrypt_frame, text="Encrypt", command=self.encrypt_text).grid(row=0, column=2, padx=5, pady=5)

        tk.Label(encrypt_frame, text="Ciphertext:").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        self.encrypted_entry = tk.Entry(encrypt_frame, textvariable=self.encrypted_var, width=70, state="readonly")
        self.encrypted_entry.grid(row=2, column=1, padx=5, pady=5)
        # "Copy Ciphertext" button beside the ciphertext field.
        tk.Button(encrypt_frame, text="Copy Ciphertext", command=self.copy_ciphertext).grid(row=2, column=2, padx=5, pady=5)

        # ---- Frame for decryption ----
        decrypt_frame = tk.LabelFrame(master, text="Decryption")
        decrypt_frame.pack(fill="both", expand="yes", padx=10, pady=5)

        # AES-256 Key field with an added Paste button beside it.
        tk.Label(decrypt_frame, text="AES-256 Key:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.decrypt_key_entry = tk.Entry(decrypt_frame, width=70)
        self.decrypt_key_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(decrypt_frame, text="Paste Key", command=self.paste_key).grid(row=0, column=2, padx=5, pady=5)

        tk.Label(decrypt_frame, text="Ciphertext:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.decrypt_cipher_entry = tk.Entry(decrypt_frame, width=70)
        self.decrypt_cipher_entry.grid(row=1, column=1, padx=5, pady=5)

        # Paste ciphertext button
        tk.Button(decrypt_frame, text="Paste Ciphertext", command=self.paste_ciphertext).grid(row=1, column=2, padx=5, pady=5)

        # "Decrypt" button spanning all columns if needed.
        tk.Button(decrypt_frame, text="Decrypt", command=self.decrypt_text).grid(row=2, column=0, columnspan=3, pady=5)

        self.decrypted_label = tk.Label(decrypt_frame, text="", fg="blue")
        self.decrypted_label.grid(row=3, column=0, columnspan=3, pady=5)

        # ---- Centered buttons ----
        # Removed the Generate New Key button from the center frame since it is now placed in the key frame.
        center_frame = tk.Frame(master)
        center_frame.pack(pady=10)

        tk.Button(master, text="Exit", command=self.exit_program).pack(pady=10)

    # ---------------------------
    #       Key Management
    # ---------------------------
    def load_key(self):
        key_text = self.load_key_entry.get().strip()
        try:
            key_bytes = bytes.fromhex(key_text)
            if len(key_bytes) != 32:
                messagebox.showerror("Error", "Key must be 64 hex characters (32 bytes).")
                return
            self.encryption_key = key_bytes
            messagebox.showinfo("Success", "Encryption key loaded successfully.")
            self.generated_key_var.set("")
        except ValueError:
            messagebox.showerror("Error", "Invalid hex key format.")

    def generate_key(self):
        key_bytes = get_random_bytes(32)
        hex_key = key_bytes.hex().upper()
        self.encryption_key = key_bytes
        self.generated_key_var.set(hex_key)

    def copy_generated_key(self):
        generated_key = self.generated_key_var.get()
        if generated_key:
            self.master.clipboard_clear()
            self.master.clipboard_append(generated_key)
            messagebox.showinfo("Copied", "Generated key copied to clipboard.")
        else:
            messagebox.showerror("Error", "No generated key to copy.")

    # ---------------------------
    #       Encryption
    # ---------------------------
    def encrypt_text(self):
        if self.encryption_key is None:
            messagebox.showerror("Error", "No encryption key is loaded. Provide or generate a key first.")
            return

        plaintext = self.encrypt_text_entry.get()
        if not plaintext:
            messagebox.showerror("Error", "Please enter some plaintext to encrypt.")
            return

        iv = get_random_bytes(16)
        cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
        combined_data = iv + ciphertext
        encoded_cipher = base64.b64encode(combined_data).decode()
        self.encrypted_var.set(encoded_cipher)

    def copy_ciphertext(self):
        ciphertext_text = self.encrypted_var.get()
        if ciphertext_text:
            self.master.clipboard_clear()
            self.master.clipboard_append(ciphertext_text)
            messagebox.showinfo("Copied", "Ciphertext copied to clipboard.")
        else:
            messagebox.showerror("Error", "No ciphertext to copy.")

    # ---------------------------
    #       Decryption
    # ---------------------------
    def paste_ciphertext(self):
        """Paste ciphertext from clipboard into the 'decrypt_cipher_entry'."""
        try:
            content = self.master.clipboard_get()
            self.decrypt_cipher_entry.delete(0, tk.END)
            self.decrypt_cipher_entry.insert(0, content)
        except Exception as e:
            messagebox.showerror("Error", f"Could not paste from clipboard: {e}")

    def paste_key(self):
        """Paste clipboard contents into the AES-256 key field."""
        try:
            content = self.master.clipboard_get()
            self.decrypt_key_entry.delete(0, tk.END)
            self.decrypt_key_entry.insert(0, content)
        except Exception as e:
            messagebox.showerror("Error", f"Could not paste key from clipboard: {e}")

    def decrypt_text(self):
        key_text = self.decrypt_key_entry.get().strip()
        cipher_b64 = self.decrypt_cipher_entry.get().strip()

        if not key_text or not cipher_b64:
            messagebox.showerror("Error", "Please enter both the hex key and base64 ciphertext.")
            return

        try:
            key_bytes = bytes.fromhex(key_text)
            if len(key_bytes) != 32:
                messagebox.showerror("Error", "Key must be 64 hex characters (32 bytes).")
                return
        except ValueError:
            messagebox.showerror("Error", "Invalid hex key format.")
            return

        try:
            combined_data = base64.b64decode(cipher_b64)
            iv = combined_data[:16]
            actual_ciphertext = combined_data[16:]
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
            decrypted = unpad(cipher.decrypt(actual_ciphertext), AES.block_size)
            self.decrypted_label.config(text=f"Decrypted text:\n{decrypted.decode('utf-8')}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def exit_program(self):
        self.master.destroy()

def main():
    root = tk.Tk()
    app = AesEncryptionGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()