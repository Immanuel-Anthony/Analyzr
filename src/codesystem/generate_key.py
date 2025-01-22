import secrets

def generate_secret_key():
    secret_key = secrets.token_hex(24)
    print("Generated Flask Secret Key:")
    print(secret_key)
    print("\nAdd this to your .env file as:")
    print(f"FLASK_SECRET_KEY={secret_key}")

if __name__ == "__main__":
    generate_secret_key()