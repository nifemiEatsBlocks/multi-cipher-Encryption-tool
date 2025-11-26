import customtkinter as ctk
from tkinter import messagebox
import sys
import ast
import hashlib


ctk.set_appearance_mode("Dark")  
ctk.set_default_color_theme("blue")  


try:
    import caesar
    import atbash
    import vigenere
    import rail_fence
    import playfair
    import affine
    import AES
    import RSA
    import xor
    import autokey
    import baconian
    import beaufort
    import bifid
    import columnarTranspositionCipher
    import feistel_cipher
    import polybius
    import RC4
    import morse
except ImportError as e:
    print(f"System Warning: Could not import a module: {e}")

COLOR_BG = '#121212'
COLOR_FRAME = "#1E1E1E"
COLOR_ACCENT = "#00FF99"
COLOR_INPUT = "#000000"
FONT_MONO = ("Consolas", 13)


class CipherApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        
        self.title('Universal Encryption Tool 🔐')
        self.geometry('750x900')
        self.configure(fg_color = COLOR_BG)
        
        
        
        self.header_font = ("Roboto Medium", 24)
        self.label_font = ("Roboto Medium", 14)
        self.entry_font = ("Roboto", 12)

        
        self.title_label = ctk.CTkLabel(self, text="Universal Encryption Tool", font=("Consolas", 24, "bold"), text_color= COLOR_ACCENT)
        self.title_label.pack(pady=20)

        
        self.main_frame = ctk.CTkScrollableFrame(self, width=600, height=750,fg_color=COLOR_FRAME,scrollbar_button_color=COLOR_ACCENT,corner_radius=15)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=10)

        
        self.cipher_map = {
            "Caesar Cipher": "1_key_int",
            "Atbash Cipher": "no_key",
            "Vigenere Cipher": "1_key_str",
            "Rail Fence": "1_key_int",
            "Playfair": "1_key_str",
            "Affine Cipher": "2_keys_int",    
            "RSA (Public Key)": "2_keys_rsa", 
            "AES (Modern)": "1_key_aes",
            "XOR Cipher": "1_key_str",
            "Autokey Cipher": "1_key_str",
            "Baconian": "no_key",
            "Beaufort Cipher": "1_key_str",
            "Bifid Cipher": "1_key_str",
            "Columnar Transposition Cipher": "1_key_str",
            "Feistel Cipher":  "2_keys_feistel",
            "Polybius Cipher": "no_key",
            "RC4 Cipher": "1_key_str",
            "SHA-256": "Hash",
            "Morse Code": "no_key"
        }

        
        self.select_label = ctk.CTkLabel(self.main_frame, text="Select Algorithm:", font=self.label_font)
        self.select_label.pack(pady=(10, 5), anchor="w", padx=20)
        
        self.selected_cipher = ctk.StringVar(value="Caesar Cipher")
        options = sorted(list(self.cipher_map.keys()))
        
        self.dropdown = ctk.CTkOptionMenu(
            self.main_frame, 
            values=options, 
            command=self.update_ui,
            width=300,
            height=40
        )
        self.dropdown.set("Caesar Cipher")
        self.dropdown.pack(pady=5)

        self.input_header = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.input_header.pack(fill="x", padx=20, pady=(20, 5))


        self.input_label = ctk.CTkLabel(self.input_header, text="Input Text:", font=self.label_font)
        self.input_label.pack(side="left")

        self.copy_input_btn = ctk.CTkButton(
        self.input_header,
        text="📋 COPY",
        width=60,
        height=20,
        font=("Consolas", 10, "bold"),
        fg_color="#333333",
        hover_color="#555555",
        command=lambda: self.copy_to_clipboard(self.input_text, self.copy_input_btn)
    )
        self.copy_input_btn.pack(side="right")
        
        self.input_text = ctk.CTkTextbox(self.main_frame, height=120, font=FONT_MONO,fg_color=COLOR_INPUT,text_color="white",border_width=1,border_color="#444444")
        self.input_text.pack(fill="x", padx=20)

        #  KEY AREA 
        self.key_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.key_frame.pack(pady=20, fill="x", padx=20)

        # Key 1
        self.key_1_box = ctk.CTkFrame(self.key_frame, fg_color="transparent")
        self.key_1_box.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        self.key_label_1 = ctk.CTkLabel(self.key_1_box, text="Key 1:", anchor="w")
        self.key_label_1.pack(fill="x")
        self.key_entry_1 = ctk.CTkEntry(self.key_1_box, placeholder_text="Enter Key...")
        self.key_entry_1.pack(fill="x")

        # Key 2
        self.key_2_box = ctk.CTkFrame(self.key_frame, fg_color="transparent")
        self.key_2_box.pack(side="left", fill="x", expand=True, padx=(5, 0))
        
        self.key_label_2 = ctk.CTkLabel(self.key_2_box, text="Key 2:", anchor="w")
        self.key_label_2.pack(fill="x")
        self.key_entry_2 = ctk.CTkEntry(self.key_2_box, placeholder_text="Second Key...")
        self.key_entry_2.pack(fill="x")

        # Generator Button
        self.gen_btn = ctk.CTkButton(
            self.key_frame, 
            text=" Gen Key", 
            fg_color="#E6B800", 
            hover_color="#CC9900", 
            text_color="black",
            width=80,
            command=self.generate_key
        )

        # BUTTONS
        self.btn_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.btn_frame.pack(pady=10)
        
        self.encrypt_btn = ctk.CTkButton(
            self.btn_frame, 
            text="ENCRYPT",
            font=("Consolas", 14, "bold"), 
            fg_color=COLOR_ACCENT,
            text_color="black", 
            hover_color="#00CC7A",
            width=200,
            height=45,
            corner_radius=25,
            command=lambda: self.process("encrypt")
        )
        self.encrypt_btn.pack(side="left", padx=10)
        
        self.decrypt_btn = ctk.CTkButton(
            self.btn_frame, 
            text="DECRYPT",
            font=("Consolas", 14, "bold"),
            fg_color="#333333", 
            hover_color="#555555",
            width=200,
            height=45,
            corner_radius=25,
            command=lambda: self.process("decrypt")
        )
        self.decrypt_btn.pack(side="left", padx=10)

        # OUTPUT AREA
        self.output_header = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.output_header.pack(fill="x", padx=20, pady=(20, 5))

        self.output_label = ctk.CTkLabel(self.output_header, text="Output Result:", font=self.label_font)
        self.output_label.pack(side="left")
        
        self.copy_output_btn = ctk.CTkButton(
            self.output_header,
            text="📋 COPY",
            width=60,
            height=20,
            font=("Consolas", 10, "bold"),
            fg_color="#333333",
            hover_color="#555555",
            command=lambda: self.copy_to_clipboard(self.output_text, self.copy_output_btn)
        )
        self.copy_output_btn.pack(side="right")

        self.output_text = ctk.CTkTextbox(self.main_frame, height=120,font=FONT_MONO, fg_color=COLOR_INPUT, text_color=COLOR_ACCENT,border_width = 1,border_color=COLOR_ACCENT)
        self.output_text.pack(fill="x", padx=20, pady=(0, 20))

        
        self.update_ui("Caesar Cipher")

    def update_ui(self, selection):
        mode = self.cipher_map[selection]

        
        self.key_frame.pack(pady=20, fill="x", padx=20)
        self.key_1_box.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.key_2_box.pack_forget()
        self.gen_btn.pack_forget()
        
        
        self.encrypt_btn.configure(text="⬇️ ENCRYPT", state="normal", fg_color="#2CC985")
        self.decrypt_btn.configure(text="⬆️ DECRYPT", state="normal", fg_color="#3B8ED0")

        if mode == "no_key":
            self.key_frame.pack_forget()
            
        elif mode == "1_key_int":
            self.key_label_1.configure(text="Key (Number):")
            
        elif mode == "1_key_str":
            self.key_label_1.configure(text="Key (Text):")
            
        elif mode == "2_keys_int":
            self.key_1_box.pack(side="left", fill="x", expand=True, padx=(0, 5))
            self.key_2_box.pack(side="left", fill="x", expand=True, padx=(5, 0))
            self.key_label_1.configure(text="Key A:")
            self.key_label_2.configure(text="Key B:")

        elif mode == "1_key_aes":
            self.key_label_1.configure(text="AES Key:")
            self.gen_btn.pack(side="left", padx=(10, 0))

        elif mode == "2_keys_feistel":
            self.key_2_box.pack(side="left", fill="x", expand=True, padx=(5, 0))
            self.key_label_1.configure(text="Secret Key:")
            self.key_label_2.configure(text="Rounds (4-16):")
            self.key_entry_2.delete(0, "end")
            self.key_entry_2.insert(0, "4")

        elif mode == "2_keys_rsa":
            self.key_2_box.pack(side="left", fill="x", expand=True, padx=(5, 0))
            self.key_label_1.configure(text="Key (e / d):")
            self.key_label_2.configure(text="Modulus (n):")
            self.gen_btn.pack(side="left", padx=(10, 0))

        if mode == "Hash":
            self.key_frame.pack_forget()
            self.encrypt_btn.configure(text="#️⃣ HASH", fg_color="#9933FF")
            self.decrypt_btn.configure(text="⛔ ONE-WAY", state="disabled", fg_color="gray")

    def generate_key(self):
        algo = self.dropdown.get()
        
        if algo == "AES (Modern)":
            key = AES.generate_aes_key()
            self.key_entry_1.delete(0, "end")
            self.key_entry_1.insert(0, key.decode())
            
        elif algo == "RSA (Public Key)":
            pub, priv = RSA.generate_rsa_keys(61, 53)
            messagebox.showinfo("RSA Keys Generated", 
                f"KEYS GENERATED\n\n"
                f"PUBLIC:  e={pub[0]}, n={pub[1]}\n"
                f"PRIVATE: d={priv[0]}, n={priv[1]}\n\n"
                "Private key not auto-filled. Write it down!")
            
            self.key_entry_1.delete(0, "end")
            self.key_entry_1.insert(0, str(pub[0]))
            self.key_entry_2.delete(0, "end")
            self.key_entry_2.insert(0, str(pub[1]))

    def copy_to_clipboard(self, textbox, button):
        try:
            text = textbox.get("1.0", "end-1c")
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update()
            
            # Visual feedback
            original_text = button.cget("text")
            button.configure(text="✅ COPIED", fg_color=COLOR_ACCENT, text_color="black")
            
            # Revert button after 1 second
            self.after(1000, lambda: button.configure(text=original_text, fg_color="#333333", text_color="white"))
        except:
            pass

    def process(self, mode):
        algo = self.dropdown.get()
        text = self.input_text.get("1.0", "end-1c").strip()
        k1 = self.key_entry_1.get().strip()
        k2 = self.key_entry_2.get().strip()

        if not text:
            return
        
        result = ""

        try:
            if algo == "Caesar Cipher":
                shift = int(k1)
                direction = "encrypt" if mode == "encrypt" else "decrypt"
                result = caesar.caesar(shift , text, direction)

            elif algo == "Atbash Cipher":
                result = atbash.atbash_cipher(text)

            elif algo == "Vigenere Cipher":
                direction = "encrypt" if mode == "encrypt" else "decrypt"
                result = vigenere.vigenere(k1, text, direction)

            elif algo == "Rail Fence":
                rails = int(k1)
                if mode == "encrypt": result = rail_fence.cipher_encryption(text, rails)
                else: result = rail_fence.cipher_decryption(text, rails)

            elif algo == "Playfair":
                if mode == "encrypt": result = playfair.playfair_encrypt(text, k1)
                else: result = playfair.playfair_decrypt(text, k1)

            elif algo == "Affine Cipher":
                a = int(k1)
                b = int(k2)
                if mode == "encrypt": result = affine.affine_encrypt(text, a, b)
                else: result = affine.affine_decrypt(text, a, b)

            elif algo == "AES (Modern)":
                key_bytes = k1.encode()
                if mode == "encrypt": result = AES.aes_encrypt(text, key_bytes)
                else: result = AES.aes_decrypt(text, key_bytes)

            elif algo == "RSA (Public Key)":
                key_tuple = (int(k1), int(k2))
                if mode == "encrypt":
                    encrypted_list = RSA.rsa_encrypt(text, key_tuple)
                    result = str(encrypted_list)
                else:
                    input_data = ast.literal_eval(text)
                    result = RSA.rsa_decrypt(input_data, key_tuple)

            elif algo == "XOR Cipher":
                if mode == "encrypt": result = xor.xor_encrypt(text, k1)
                else: result = xor.xor_decrypt(text, k1)

            elif algo == "Autokey Cipher":
                if mode == "encrypt": result = autokey.autokey_encrypt(text, k1)
                else: result = autokey.autokey_decrypt(text, k1)

            elif algo == "Baconian":
                if mode == "encrypt": result = baconian.baconian_encrypt(text)
                else: result = baconian.baconian_decrypt(text)

            elif algo == "Beaufort Cipher":
                result = beaufort.beaufort_cipher(text, k1)

            elif algo == "Bifid Cipher":
                if mode == "encrypt": result = bifid.bifid_encrypt(text, k1)
                else: result = bifid.bifid_decrypt(text, k1)

            elif algo == "Columnar Transposition Cipher":
                if mode == "encrypt": result = columnarTranspositionCipher.columnar_encrypt(text, k1)
                else: result = columnarTranspositionCipher.columnar_decrypt(text, k1)

            elif algo == "Feistel Cipher":
                try: rounds = int(k2)
                except ValueError: rounds = 4
                if mode == "encrypt": result = feistel_cipher.feistel_encrypt(text, k1, rounds)
                else: result = feistel_cipher.feistel_decrypt(text, k1, rounds)

            elif algo == "Polybius Cipher":
                if mode == "encrypt": result = polybius.polybius_encrypt(text)
                else: result = polybius.polybius_decrypt(text)

            elif algo == "RC4 Cipher":
                if mode == "encrypt": result = RC4.rc4_encrypt(text, k1)
                else: result = RC4.rc4_decrypt(text, k1) 

            elif algo == "SHA-256":
                encoded_text = text.encode('utf-8')
                hash_obj = hashlib.sha256(encoded_text)
                result = hash_obj.hexdigest()

            elif algo == "Morse Code":
                if mode == "encrypt":
                    result = morse.encrypt(text)
                else:
                    result = morse.decrypt(text)

            else:
                result = f"Logic for '{algo}' not connected."

            # Output
            self.output_text.delete("1.0", "end")
            self.output_text.insert("0.0", str(result))

        except ValueError:
            messagebox.showerror("Input Error", "Check your keys! Valid numbers/text required.")
        except Exception as e:
            messagebox.showerror("System Error", f"An error occurred: {str(e)}")

if __name__ == "__main__":
    app = CipherApp()
    app.mainloop()
                    
