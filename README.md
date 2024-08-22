## Bilal Ahmed
## Capstone Project


# Secure File Encryption Decryption System

This program is a simple implementation of a symmetric encryption system using the Advanced Encryption Standard (AES). It provides a graphical user interface (GUI) that allows users to encrypt and decrypt files using a single key, which must be securely shared between the Encryption and Decryption. The program eliminates the need for public-key cryptography, focusing solely on symmetric key management, making it straightforward and efficient for use cases where both parties can securely exchange the key.

The core of the program revolves around the cryptography library, which is used to handle encryption and decryption operations. The Encryption generates a 256-bit AES key and saves it to a file. This key is then used to encrypt a selected text file. The resulting encrypted file is saved with a `.enc` extension. This encrypted file and the key file can then be shared with the intended recipient securely.

When the recipient receives the encrypted file, they load the file along with the corresponding key file using the program. The program then decrypts the encrypted file using the AES key and saves the decrypted content as a new file with a `_decrypted.txt` suffix. This process ensures that only someone with access to the correct key can decrypt and read the file's contents.

The program's simplicity and ease of use make it suitable for scenarios where secure file transfer is needed, but public key infrastructure (PKI) is not available or necessary. However, the security of the system relies heavily on the safe distribution and storage of the symmetric key. If the key is exposed or intercepted, the security of the encrypted data is compromised.

## Using the Program as Encryption

1. Select the "Encryption" role in the program.
2. Follow these steps:
   - Click "Step 1: Select File" to choose the `.txt` file you want to encrypt.
   - Click "Step 2: Generate and Save Key" to create a symmetric key and save it to a `.key` file.
   - Click "Step 3: Encrypt File" to encrypt the selected file using the generated key. The encrypted file will be saved with a `.enc` extension.

## Using the Program as Decryption

1. Select the "Decryption" role in the program.
2. Follow these steps:
   - Click "Step 1: Select Encrypted File" to choose the `.enc` file you want to decrypt.
   - Click "Step 2: Select Key File" to load the corresponding `.key` file that was used for encryption.
   - Click "Step 3: Decrypt File" to decrypt the selected file using the key. The decrypted file will be saved with a `_decrypted.txt` suffix.

## Program Topological Diagram

SymmetricEncryptionApp Class
|
|-- init()
| |-- Initialize variables
| |-- Create GUI widgets
|
|-- create_widgets()
| |-- Define GUI layout
| |-- Create buttons, labels, and progress indicator
|
|-- update_role()
| |-- Reset variables
| |-- Update GUI based on role
|
|-- select_file()
| |-- Open file dialog
| |-- Select file based on role
|
|-- step2_action()
| |-- Perform action based on role
| |-- Encryption: Generate key
| |-- Decryption: Load key
|
|-- step3_action()
| |-- Perform final action based on role
| |-- Encryption: Encrypt file
| |-- Decryption: Decrypt file
|
|-- generate_key()
| |-- Generate AES key
| |-- Save key to file
|
|-- load_key()
| |-- Load AES key from file
|
|-- encrypt_file()
| |-- Encrypt selected file using AES key
| |-- Save encrypted file
|
|-- decrypt_file()
| |-- Decrypt selected file using AES key
| |-- Save decrypted file




## User Process Topological Diagram

Start Program
|
|-- Select Role
| |-- Encryption
| | |-- Step 1: Select File
| | |-- Step 2: Generate and Save Key
| | |-- Step 3: Encrypt File
| |-- Decryption
| |-- Step 1: Select Encrypted File
| |-- Step 2: Select Key File
| |-- Step 3: Decrypt File
|
|-- End Program
