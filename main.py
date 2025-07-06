from crypto_utils import encrypt_file, decrypt_file

# Example usage
password = input("Enter password: ")

# Encrypt
encrypt_file("sample_files/testfile.txt", password)

# Decrypt
decrypt_file("sample_files/testfile.txt.encrypted", password)
