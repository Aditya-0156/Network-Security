import hashlib
import random
import itertools
def hash_text(plaintext):
    # Use SHA-256 hash function to obtain the hash value
    hash_object = hashlib.sha256()
    hash_object.update(plaintext.encode('utf-8'))
    hash_value = hash_object.hexdigest()

    # Custom mapping from hexadecimal characters to 'a' to 'p'
    custom_mapping = {'0': 'a', '1': 'b', '2': 'c', '3': 'd',
                      '4': 'e', '5': 'f', '6': 'g', '7': 'h',
                      '8': 'i', '9': 'j', 'a': 'k', 'b': 'l',
                      'c': 'm', 'd': 'n', 'e': 'o', 'f': 'p'}

    # Replace each hexadecimal character with its custom mapping
    custom_hash = ''.join(custom_mapping[c] for c in hash_value)

    return custom_hash

def encrypt(plaintext):
    # Use the hash function to obtain the hash value
    hash_value=hash_text(plaintext)
    # Combine plaintext and hash value
    combined_text = f"{plaintext}{hash_value}"
    # Get a random key of size up to 9
    # key_size = random.randint(1, 9)
    # key = random.sample(range(1, key_size + 1), key_size)
    key=[8,5,4,2,3,1,6,7,9]
    # Implement transposition encryption using the random key
    ciphertext = transpose_encrypt(combined_text, key)
    return ciphertext


def transpose_encrypt(plaintext, key):
    # Pad the plaintext if its length is not a multiple of the key size
    padding = (len(plaintext) % len(key))
    if padding != 0:
        plaintext += '*' * (len(key) - padding)
    # Create the transposition matrix
    matrix = []
    for i in range(0, len(plaintext), len(key)):
        matrix.append(list(plaintext[i:i + len(key)]))
    ciphertext = ""
    i=0
    while(i<len(key)):
        for j in range(0,len(matrix)):
            ciphertext+=matrix[j][key[i]-1]
        i+=1
    return ciphertext

def transpose_decrypt(ciphertext, key):
    m=int(len(ciphertext)/len(key))
    n=len(key)
    matrix = [['*' for _ in range(n)] for _ in range(m)]
    count=0
    i=0
    while (i < len(key)):
        for j in range(0, len(matrix)):
            matrix[j][key[i] - 1]=ciphertext[count]
            count+=1
        i += 1
    deciphered_text=""
    for j in range(m):
        for k in range(n):
            if(matrix[j][k]!="*"):
                deciphered_text+=matrix[j][k]
    return deciphered_text
def check(deciphered_text):
    deciphered_hash= deciphered_text[-64:]
    deciphered_text= deciphered_text[:-64]
    if(hash_text(deciphered_text)==deciphered_hash):
        return True
    return False


def brute_force(ciphertext, output_file="decryption_results.txt"):
    with open(output_file, "w") as file:
        for key_size in range(1, 10):
            # Generate all permutations of the key
            all_permutations = list(itertools.permutations(range(1, key_size + 1)))

            for key_permutation in all_permutations:
                # Decrypt the ciphertext using the current key permutation
                decrypted_text = transpose_decrypt(ciphertext, key_permutation)

                # Save results to the file
                file.write(f"Key: {key_permutation}\n")
                file.write(f"Deciphered Text: {decrypted_text[:-64]}\n")
                file.write(f"Check Result: {check(decrypted_text)}\n\n")

                # Check if the decrypted text is valid
                if check(decrypted_text):
                    print("Decryption successful!")
                    print("Key:", key_permutation)
                    return key_permutation

    print("Brute force failed. Unable to find a valid key.")
    return None

s1="thisprojectiscreatedbyadityaandhimanshufornetworksecurity"
s2="thisprojectusestranspositiontoencryptanddecrypt"
s3="projectcontainsseveralfunctions"
s4="lengthofthekeyistakenasninewhichtakesmostamountoftimetofindusingbruteforce"
s5="thiscodeisnicelycommentedanddoesnotviolateplagiarismpolicypleasegivefullmarksthankyou"
strings_list=[]
strings_list.append(s1)
strings_list.append(s2)
strings_list.append(s3)
strings_list.append(s4)
strings_list.append(s5)
ciphertexts_list = []
print("Encrypted Text")
for string in strings_list:
    ciphertext= encrypt(string)
    ciphertexts_list.append(ciphertext)
    print(ciphertext)



# Call brute force on the first string
brute_force_key = brute_force(ciphertexts_list[0])

# Print the decrypted text for each string without the last 64 characters
for ciphertext in ciphertexts_list:
    decrypted_text = transpose_decrypt(ciphertext, brute_force_key)
    decrypted_text_without_hash = decrypted_text[:-64]
    print(decrypted_text_without_hash)