import streamlit as st
import base64
from sympy import randprime, mod_inverse

def generate_keypair():
    p = randprime(2**64, 2**65)
    q = randprime(2**64, 2**65)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  
    while True:
        d = mod_inverse(e, phi)
        if d != e:  
            break
    return ((e, n), (d, n))  # Public key, Private key

def encrypt_message(message, public_key):
    e, n = public_key
    encrypted = [pow(ord(char), e, n) for char in message]
    return encrypted

def decrypt_message(encrypted, private_key):
    d, n = private_key
    decrypted = [chr(pow(char, d, n)) for char in encrypted]
    return ''.join(decrypted)

def encrypt_file(file_contents, public_key):
    e, n = public_key
    encrypted = [pow(byte, e, n) for byte in file_contents]
    return encrypted

def decrypt_file(encrypted_contents, private_key):
    d, n = private_key
    decrypted = [pow(byte, d, n) for byte in encrypted_contents]
    return decrypted

def main():
    st.title("Simulasi Python Dengan Enkripsi RSA")

    bob_keypair = generate_keypair()
    alice_keypair = generate_keypair()

    col1, col2 = st.columns(2)
    with col1:
        st.header("Pesan Bob")
        bob_message = st.text_input("Masukan Pesan untuk Alice:")

        st.subheader("Public Key Bob:")
        st.write(bob_keypair[0])
        st.subheader("Private Key Bob:")
        st.write(bob_keypair[1])

        if bob_message:
            encrypted_bob_message = encrypt_message(bob_message, alice_keypair[0])
            base64_encrypted_bob_message = base64.b64encode(bytes(str(encrypted_bob_message), 'utf-8')).decode()

            st.write("**Pesan Terenkripsi untuk Alice dari Bob (base64):**")
            st.text(base64_encrypted_bob_message)

    with col2:
        st.header("Pesan Alice")
        alice_message = st.text_input("Masukan Pesan untuk Bob:")

        st.subheader("Public Key Alice:")
        st.write(alice_keypair[0])
        st.subheader("Public Key Bob:")
        st.write(alice_keypair[1])

        if alice_message:
            encrypted_alice_message = encrypt_message(alice_message, bob_keypair[0])
            base64_encrypted_alice_message = base64.b64encode(bytes(str(encrypted_alice_message), 'utf-8')).decode()

            st.write("**Pesan Terenkripsi untuk Bob dari Alice (base64):**")
            st.text(base64_encrypted_alice_message)

    if 'base64_encrypted_alice_message' in locals():
        st.header("Sisi Bob")
        st.write("**Pesan Ternekripsi dari Alice:**")
        st.text(base64_encrypted_alice_message)

        decrypted_alice_message = decrypt_message(encrypted_alice_message, bob_keypair[1])
        st.write("**Dekripsi pesan dari Alice:**")
        st.success(decrypted_alice_message)

    if 'base64_encrypted_bob_message' in locals():
        st.header("Sisi Alice")
        st.write("**Pesan Terenkripsi dari Bob:**")
        st.text(base64_encrypted_bob_message)

        decrypted_bob_message = decrypt_message(encrypted_bob_message, alice_keypair[1])
        st.write("**Dekripsi pesan dari  Bob:**")
        st.success(decrypted_bob_message)

    file_to_encrypt = st.file_uploader("Masukkan File untuk dienkripsi:")
    if file_to_encrypt:
        encrypted_file = encrypt_file(file_to_encrypt.getvalue(), alice_keypair[0])
        st.write("**Masukkan File untuk dienkripsi**")
        st.download_button("Download File terenkripsi", base64.b64encode(bytes(str(encrypted_file), 'utf-8')).decode(), file_name="encrypted_file.bin")

    file_to_decrypt = st.file_uploader("Masukkan File untuk didekripsi:")
    if file_to_decrypt:
        decrypted_file = decrypt_file(file_to_decrypt.getvalue(), bob_keypair[1])
        st.write("**Masukkan File untuk didekripsi**")
        st.download_button("Download File terdekripsi", bytes(decrypted_file), file_name="decrypted_file.txt")

if __name__ == "__main__":
    main()
