# AES S-box
Sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Rcon table
Rcon = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]


def KeyExpansion(key):
    w = [0] * 44
    round_keys = []

    for i in range(4):
        w[i] = (key[4 * i] << 24) + (key[4 * i + 1] << 16) + (key[4 * i + 2] << 8) + key[4 * i + 3]

    for i in range(0, 44):
        temp = w[i - 1]
        if i % 4 == 0:
            temp = SubWord(RotWord(temp)) ^ Rcon[i // 4]
        w[i] = w[i - 4] ^ temp

        # Extract round key
        if i % 4 == 0:
            round_key = ''.join(format(w[j], '08x') for j in range(i - 3, i + 1))
            round_keys.append(round_key)

    return round_keys

def RotWord(word):
    return ((word << 8) & 0xffffffff) | ((word >> 24) & 0xff)

def SubWord(word):
    return (Sbox[word >> 24] << 24) | (Sbox[(word >> 16) & 0xff] << 16) | \
           (Sbox[(word >> 8) & 0xff] << 8) | (Sbox[word & 0xff])

def add_round_key(state, round_key):
    new_state = []
    for i in range(len(state)):
        # Convert state and round_key bytes to integers
        state_byte = state[i]
        round_key_byte = int(round_key[i*2:i*2+2], 16)

        # XOR operation
        new_byte = state_byte ^ round_key_byte

        new_state.append(new_byte)

    return new_state
def sub_bytes(state):
    new_state = []
    for byte in state:
        # Apply S-box substitution
        new_byte = Sbox[byte]
        new_state.append(new_byte)
    return new_state
def shift_rows(state):
    new_state = [
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11]
    ]
    return new_state
def mix_columns(state):
    new_state = [0] * 16

    for col in range(4):
        new_state[col] = (
            multiply(0x02, state[col]) ^
            multiply(0x03, state[4 + col]) ^
            state[8 + col] ^
            state[12 + col]
        )
        new_state[4 + col] = (
            state[col] ^
            multiply(0x02, state[4 + col]) ^
            multiply(0x03, state[8 + col]) ^
            state[12 + col]
        )
        new_state[8 + col] = (
            state[col] ^
            state[4 + col] ^
            multiply(0x02, state[8 + col]) ^
            multiply(0x03, state[12 + col])
        )
        new_state[12 + col] = (
            multiply(0x03, state[col]) ^
            state[4 + col] ^
            state[8 + col] ^
            multiply(0x02, state[12 + col])
        )

    return new_state

def multiply(x, y):
    """
    Multiplication in GF(2^8) for mix_columns operation in AES.

    Args:
    - x, y: Bytes to be multiplied.

    Returns:
    - result: Result of multiplication.
    """
    # Initialize result
    result = 0

    # Perform multiplication
    while y:
        # If y is odd, add x to result
        if y & 1:
            result ^= x

        # Multiply x by 2 in GF(2^8)
        x <<= 1

        # Reduce x modulo the AES irreducible polynomial (x^8 + x^4 + x^3 + x + 1)
        if x & 0x100:
            x ^= 0x11b  # XOR with the AES irreducible polynomial

        # Shift y one bit to the right (divide by 2)
        y >>= 1

    return result
def encrypt_block(plaintext_block, round_keys):
    state = plaintext_block

    # Initial round
    state = add_round_key(state, round_keys[0])

    # Main rounds
    with open('log.txt', 'a') as file:
        file.write("Encrpytion" + "\n")
        for i, round_key in enumerate(round_keys[1:-1], 1):
            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, round_key)
            # Write round number and state to file
            file.write("Round number " + str(i) + ":\n")
            file.write(str(state) + "\n")

        # Final round (no mix_columns)
        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, round_keys[-1])

        # Write final round number and state to file
        file.write("Final round:\n")
        file.write(str(state) + "\n")

    return state


def decrypt_block(ciphertext_block, round_keys):
    state = ciphertext_block

    # Initial round (same as final round in encryption)
    state = add_round_key(state, round_keys[-1])

    # Main rounds
    i = 1
    with open('log.txt', 'a') as file:
        file.write("Decrpytion" + "\n")
        for j in range(len(round_keys) - 2, 0, -1):
            round_key = round_keys[j]
            state = inverse_shift_rows(state)
            state = inverse_sub_bytes(state)
            file.write("Round number " + str(i) + ":\n")
            file.write(str(state) + "\n")
            state = add_round_key(state, round_key)
            state = inverse_mix_columns(state)

            i += 1

    # Final round
    state = inverse_shift_rows(state)
    state = inverse_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    # Write final round number and state to file
    with open('log.txt', 'a') as file:
        file.write("Final round:\n")
        file.write(str(state) + "\n")

    return state

def inverse_shift_rows(state):
    new_state = [
        state[0], state[13], state[10], state[7],
        state[4], state[1], state[14], state[11],
        state[8], state[5], state[2], state[15],
        state[12], state[9], state[6], state[3]
    ]
    return new_state

def inverse_sub_bytes(state):
    new_state = []
    for byte in state:
        # Apply inverse S-box substitution
        new_byte = InverseSbox[byte]
        new_state.append(new_byte)
    return new_state

def inverse_mix_columns(state):
    new_state = [0] * 16

    for col in range(4):
        new_state[col] = (
            multiply(0x0e, state[col]) ^
            multiply(0x0b, state[4 + col]) ^
            multiply(0x0d, state[8 + col]) ^
            multiply(0x09, state[12 + col])
        )
        new_state[4 + col] = (
            multiply(0x09, state[col]) ^
            multiply(0x0e, state[4 + col]) ^
            multiply(0x0b, state[8 + col]) ^
            multiply(0x0d, state[12 + col])
        )
        new_state[8 + col] = (
            multiply(0x0d, state[col]) ^
            multiply(0x09, state[4 + col]) ^
            multiply(0x0e, state[8 + col]) ^
            multiply(0x0b, state[12 + col])
        )
        new_state[12 + col] = (
            multiply(0x0b, state[col]) ^
            multiply(0x0d, state[4 + col]) ^
            multiply(0x09, state[8 + col]) ^
            multiply(0x0e, state[12 + col])
        )

    return new_state

# Define AES inverse S-box
InverseSbox = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]


def main():
    key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x97, 0x86, 0x65, 0x8f, 0xc4, 0x62]

    # Expand the key
    round_keys = KeyExpansion(key)

    plaintext_strings = [
        "This system is made Aditya & Himanshu",
        "This project is for AES-128 which takes a 128bit key and has 10 rounds",
        "This is a test string of arbitrary length. Let's see how AES handles it!"
    ]
    i=0
    for plaintext_string in plaintext_strings:
        file=open('log.txt', 'a')
        file.write("Plaintext " + str(i + 1) + "\n")
        file.write(plaintext_string + "\n")
        file.close()
        print("Plaintext ", i + 1)
        print(plaintext_string)
        # Convert the plaintext string to hexadecimal
        plaintext_hex = plaintext_string.encode().hex()

        # Break the hexadecimal representation into 128-bit (16 bytes) blocks
        plaintext_blocks = [plaintext_hex[i:i + 32] for i in range(0, len(plaintext_hex), 32)]

        # Pad the last block if necessary
        if len(plaintext_blocks[-1]) < 32:
            plaintext_blocks[-1] += 'f' * (32 - len(plaintext_blocks[-1]))

        # Encrypt each block separately
        ciphertext_blocks = []
        for block in plaintext_blocks:
            # Convert hexadecimal block to a list of integers representing bytes
            hex_block = [int('0x' + block[i:i + 2], 16) for i in range(0, 32, 2)]

            # Encrypt the block
            ciphertext_blocks.append(encrypt_block(hex_block, round_keys))

        # Decrypt each ciphertext block separately
        decrypted_blocks = []
        for block in ciphertext_blocks:
            decrypted_blocks.append(decrypt_block(block, round_keys))

        # Join the decrypted blocks to get the text in hexadecimal representation
        decrypted_hex_text = ''.join(['{:02x}'.format(byte) for block in decrypted_blocks for byte in block])

        # Convert the hexadecimal representation back to the original text and print it
        decrypted_text = bytes.fromhex(decrypted_hex_text).decode('utf-8', errors='ignore')
        print("Decrypted plaintext string:")
        print(decrypted_text)
        i += 1


if __name__ == "__main__":
    main()