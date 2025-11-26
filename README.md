**Universal Encryption Tool**
Version: 1.0
**Overview**:
A standalone desktop application developed in Python for encrypting, decrypting, and hashing text data. The tool provides a unified graphical interface for 18 different algorithms, ranging from classical ciphers to modern security standards.
**
Supported Algorithms**:
Classical: Caesar, Vigenère, Atbash, Rail Fence, Playfair, Affine, Beaufort, Bifid, Polybius.
Modern: AES (Advanced Encryption Standard), RSA (Public/Private Key), Feistel, RC4.
Encoding & Hashing: Morse Code, SHA-256, XOR, Base64.

**Features**:
GUI: Built with CustomTkinter for system-aware Light/Dark mode.

Key Generation: Automated generation for AES keys and RSA key pairs.

Utilities: Clipboard integration and input/output swapping.

Validation: Input validation for specific cipher requirements (e.g., integer keys vs string keys).

**How to Run**:
Method 1: Executable (Windows)
Download and extract the project ZIP file or app directly in the realeases.
Run EncryptionTool.exe.

Note: If Windows SmartScreen prompts that the app is unrecognized, click "More Info" and then "Run Anyway". This occurs because the application is not digitally signed.

Method 2: Source Code
Ensure Python 3.10+ is installed.
Install dependencies: pip install customtkinter pycryptodome
Run the main script: python app.py

Dependencies
Python 3.x
CustomTkinter
PyCryptodome

Disclaimer
This application is for educational purposes. The cryptographic implementations should not be used for securing sensitive real-world data
