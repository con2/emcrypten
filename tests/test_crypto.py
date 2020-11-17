from emcrypten.crypto import (
    generate_symmetric_key,
    encrypt_symmetric,
    decrypt_symmetric,
    generate_asymmetric_key,
    encrypt_asymmetric,
    decrypt_asymmetric,
    reencrypt_private_key,
)


def test_symmetric():
    key = generate_symmetric_key()
    plain_bytes = b'hello, world'
    cipher_bytes = encrypt_symmetric(plain_bytes, key)
    decrypted_bytes = decrypt_symmetric(cipher_bytes, key)
    assert decrypted_bytes == plain_bytes


def test_asymmetric():
    # the payload we want to encrypt asymmetrically is actually fernet keys
    plain_bytes = generate_symmetric_key()

    # conveniently use fernet keys as passwords also
    old_password = generate_symmetric_key()
    new_password = generate_symmetric_key()

    private_key, public_key = generate_asymmetric_key(old_password)
    cipher_bytes = encrypt_asymmetric(plain_bytes, public_key)

    # hey, let's change the private key password
    private_key = reencrypt_private_key(private_key, old_password, new_password)

    decrypted_bytes = decrypt_asymmetric(cipher_bytes, private_key, new_password)

    assert decrypted_bytes == plain_bytes
