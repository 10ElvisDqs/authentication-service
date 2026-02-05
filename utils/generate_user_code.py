import secrets

def generate_user_code():
    # 12 dígitos reales, nunca se repiten en práctica
    return secrets.randbelow(10**12)