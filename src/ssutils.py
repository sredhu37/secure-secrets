#############################################
# Variables naming convention               #
# o     => object                           #
# s     => string                           #
# by    => bytes                            #
# l     => list                             #
# d     => dictionary                       #
#############################################

from cryptography.fernet import Fernet
import yaml, base64, os, subprocess


def get_latest_cryption_secret(l_secrets_in_namespace, s_namespace, s_secret):
    l_secrets_with_substring = list(filter(lambda x: s_secret in x.metadata.name, l_secrets_in_namespace))
    l_secrets_with_substring.sort(key = lambda x: x.metadata.creation_timestamp, reverse=True)

    if len(l_secrets_with_substring) == 0:
        exit(f"Error: Unable to find a secret whose metadata.name has: {s_secret}")

    o_latest_cryption_secret = l_secrets_with_substring[0]

    try:
        o_fernet_key = Fernet(base64.b64decode((o_latest_cryption_secret.data)["fernet_key"]))
    except KeyError as exc:
        exit(f"Invalid key! Please choose a Fernet key. KeyError: {exc}")
    return (o_latest_cryption_secret, o_fernet_key)

def encrypt_text(o_fernet_key, s_text):
    by_encrypted_text = o_fernet_key.encrypt(s_text.encode())
    return by_encrypted_text.decode()

def decrypt_text(o_fernet_key, s_text):
    by_decrypted_text = o_fernet_key.decrypt(s_text.encode())
    return by_decrypted_text.decode()

def cleanup_file(s_filepath):
    if os.path.exists(s_filepath):
        os.remove(s_filepath)

def encrypt_secrets(o_cryption_secret, o_fernet_key, l_secrets_to_encrypt):
    # print(f"Secrets to encrypt: {l_secrets_to_encrypt}")
    o_secure_secret = []
    for secret in l_secrets_to_encrypt:
        with open('securesecret-template.yaml', 'r') as ss_tempate_stream:
            try:
                o_secure_secret.append(yaml.safe_load(ss_tempate_stream))
            except yaml.YAMLError as exc:
                exit("Something wrong with reading securesecret-template.yaml. Please mail the administrator on redhu.sunny1994@gmail.com immediately: {exc}")

        o_secure_secret[-1]['metadata']['name'] = secret.metadata.name
        o_secure_secret[-1]['metadata']['namespace'] = secret.metadata.namespace
        o_secure_secret[-1]['spec']['secretType'] = secret.type
        o_secure_secret[-1]['spec']['decryptionKeyName'] = o_cryption_secret.metadata.name

        for key, value in secret.data.items():
            s_encrypted_text = encrypt_text(o_fernet_key, base64.b64decode(value).decode())
            s_encrypted_text_b64_encoded = base64.b64encode(s_encrypted_text.encode()).decode()
            s_decrypted_text = decrypt_text(o_fernet_key, base64.b64decode(s_encrypted_text_b64_encoded).decode())
            s_decrypted_text_b64_encoded = base64.b64encode(s_decrypted_text.encode()).decode()

            if s_decrypted_text_b64_encoded == value:
                o_secure_secret[-1]['spec']['data'].append({"key": key, "value": s_encrypted_text_b64_encoded})
            else:
                print(f"Original value: {value}")
                print(f"Decrypted value: {s_decrypted_text_b64_encoded}")
                exit("Something wrong with encryption! Please mail the administrator on redhu.sunny1994@gmail.com immediately.")

    s_temp_output_filename = 'secure_secrets.yaml'
    cleanup_file(s_temp_output_filename)

    with open(s_temp_output_filename, 'w') as file:
        try:
            yaml.dump_all(o_secure_secret, file, default_flow_style=False)
        except yaml.YAMLError as exc:
            print(exc)
    print()     # Empty line
    subprocess.run(f"cat {s_temp_output_filename}", shell=True, check=True)
    cleanup_file(s_temp_output_filename)

def decrypt_secure_secrets(o_fernet_key, l_secrets_to_decrypt):
    pass
