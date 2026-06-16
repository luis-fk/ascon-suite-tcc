import secrets

# Gera 16 bytes de entropia segura do Sistema Operacional
chave = secrets.token_bytes(16)

# Imprime no formato do array em C para o Arduino
array_c = ", ".join([f"0x{b:02x}" for b in chave])
print(f"const unsigned char key[ASCON128_KEY_SIZE] = {{\n    {array_c}\n}};")