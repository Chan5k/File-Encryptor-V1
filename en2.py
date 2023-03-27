import os
from tkinter import *
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE = 16

class FileEncrypter:
    def __init__(self, master):
        self.master = master
        master.title("File Encrypter")

        Label(master, text="Encryption Key (16, 24, or 32 bytes):").grid(row=0, column=0, sticky=W)
        self.entry_key = Entry(master)
        self.entry_key.grid(row=0, column=1)
        Button(master, text="Generate Key", command=self.generate_key).grid(row=0, column=2)

        Label(master, text="Input File:").grid(row=1, column=0, sticky=W)
        self.entry_input_file = Entry(master)
        self.entry_input_file.grid(row=1, column=1)
        Button(master, text="Browse", command=self.browse_input_file).grid(row=1, column=2)

        Label(master, text="Output File:").grid(row=2, column=0, sticky=W)
        self.entry_output_file = Entry(master)
        self.entry_output_file.grid(row=2, column=1)
        Button(master, text="Browse", command=self.browse_output_file).grid(row=2, column=2)

        Button(master, text="Encrypt File", command=self.encrypt_file).grid(row=3, column=1)

    def generate_key(self):
        self.entry_key.delete(0, END)
        self.entry_key.insert(0, os.urandom(32).hex())

    def browse_input_file(self):
        self.entry_input_file.delete(0, END)
        self.entry_input_file.insert(0, filedialog.askopenfilename())

    def browse_output_file(self):
        self.entry_output_file.delete(0, END)
        self.entry_output_file.insert(0, filedialog.asksaveasfilename(defaultextension=".enc"))

    def encrypt_file(self):
        key_hex, input_file_path, output_file_path = self.entry_key.get(), self.entry_input_file.get(), self.entry_output_file.get()
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            messagebox.showerror("Error", "Invalid key.")
            return

        if not os.path.isfile(input_file_path):
            messagebox.showerror("Error", "Input file does not exist.")
            return

        iv = os.urandom(BLOCK_SIZE)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        with open(input_file_path, 'rb') as in_file, open(output_file_path, 'wb') as out_file:
            out_file.write(os.path.getsize(input_file_path).to_bytes(8, 'big'))
            out_file.write(iv)
            while True:
                chunk = in_file.read(1024 * BLOCK_SIZE)
                if not chunk:
                    break
                elif len(chunk) % BLOCK_SIZE != 0:
                    chunk += b' ' * (BLOCK_SIZE - len(chunk) % BLOCK_SIZE)
                out_file.write(encryptor.update(chunk))

root = Tk()
FileEncrypter(root)
root.mainloop()
