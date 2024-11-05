from passlib.context import CryptContext

# Create a password context with bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(plain_password):
    """
    Hash a plain text password.

    Args:
        plain_password (str): The plain text password to hash.

    Returns:
        str: The hashed password.
    """
    return pwd_context.hash(plain_password)

def verify_password(plain_password, hashed_password):
    """
    Verify a plain text password against a hashed password.

    Args:
        plain_password (str): The plain text password to verify.
        hashed_password (str): The hashed password to compare against.

    Returns:
        bool: True if the plain password matches the hashed password,
              False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)

# Example usage
if __name__ == "__main__":
    # Registering a user (hashing the password)
    password = "Hello123"
    hashed = hash_password(password)
    print(f"Hashed Password: {hashed}")

    # Authenticating a user (verifying the password)
    plain_password_input = "Hello123"
    if verify_password(plain_password_input, hashed):
        print("Password is valid!")
    else:
        print("Invalid password!")
