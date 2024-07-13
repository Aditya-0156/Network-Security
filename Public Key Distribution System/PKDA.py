import random
import math
from datetime import datetime

def generate_prime_candidate(length):
    """Generate an odd integer randomly."""
    p = random.getrandbits(length)
    # apply a mask to set MSB and LSB to 1
    p |= (1 << length - 1) | 1
    return p

def is_prime(n, k=128):
    """Test if a number is prime using Miller-Rabin primality test."""
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    # Find r, s such that n-1 = 2^r * s
    s = n - 1
    r = 0
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime_number(length=100):
    """Generate a prime number of given bit length."""
    p = 4
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
    return p

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    m0 = phi
    y = 0
    x = 1

    if phi == 1:
        return 0

    while e > 1:
        q = e // phi
        t = phi

        phi = e % phi
        e = t
        t = y

        y = x - q * y
        x = t

    if x < 0:
        x += m0

    return x

def generate_keys():
    p = generate_prime_number(100)
    q = generate_prime_number(100)
    n = p * q
    phi = (p-1) * (q-1)

    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    d = multiplicative_inverse(e, phi)

    return ((e, n), (d, n))
def attach(objects):

    inner_delimiter = "|"
    outer_delimiter = "||"

    result = []
    for obj in objects:
        if isinstance(obj, (str, int)):
            # Directly append strings and integers
            result.append(str(obj))  # Convert integers to strings
        elif isinstance(obj, tuple):
            # Convert tuple elements to string and join with inner delimiter
            result.append(inner_delimiter.join(map(str, obj)))
        else:
            raise TypeError(f"Unsupported object type: {type(obj)}")

    # Join all objects with outer delimiter and return
    return outer_delimiter.join(result)


def detach(s):

    outer_delimiter = "||"
    inner_delimiter = "|"

    objects = s.split(outer_delimiter)
    result = []
    for obj in objects:
        if inner_delimiter in obj:
            # Convert back to tuple if inner delimiter is found
            tuple_elements = obj.split(inner_delimiter)
            result.append(tuple(int(x) if x.isdigit() else x for x in tuple_elements))
        else:
            # Check if the object is an integer or a string
            result.append(int(obj) if obj.isdigit() else obj)

    return result
def encrypt(pk, plaintext):
    key, n = pk
    cipher = [pow(ord(char), key, n) for char in plaintext]
    return cipher

def decrypt(pk, ciphertext):
    key, n = pk
    plain = [chr(pow(char, key, n)) for char in ciphertext]
    return ''.join(plain)
# PKDA Server
class PKDA:
    def __init__(self):
        self.private_key, self.public_key = generate_keys()
        self.client_public_keys = {}

    def register_client(self, client_id, client_pub_key):
        self.client_public_keys[client_id] = client_pub_key


    def get_encrypted_public_key(self, request):
        detach1=detach(request)
        key=self.client_public_keys.get(detach1[0])
        detach1.insert(0, key)
        attach1=attach(detach1)
        encrypt1=encrypt(self.private_key,attach1)
        return encrypt1

def simulate(pkda,initiator,responder):
    initiator.request_public_key(pkda,responder.id)
    initiator.send_message(responder)
    responder.receive_message(pkda,responder)
    responder.send_message(initiator)
    initiator.receive_message(pkda,responder)
    responder.confrim()

# Client
class Client:
    def __init__(self,id, pkda_public_key):
        self.private_key, self.public_key = generate_keys()
        self.pkda_public_key = pkda_public_key
        self.other_public_key = None
        self.request=None
        self.id=id
        self.message=None
        self.nonce=None
        self.inbox=None
        self.other_id=None

    def request_public_key(self, pkda, responder_id):
        request=[]
        self.other_id=responder_id
        # Get current datetime object
        now = datetime.now()
        # Convert datetime object to timestamp
        timestamp = str(datetime.timestamp(now))
        request.append(responder_id)
        request.append(timestamp)
        attach1=attach(request)
        encrypted_key=pkda.get_encrypted_public_key(attach1)
        decrypted_key=decrypt(self.pkda_public_key,encrypted_key)
        detach1=detach(decrypted_key)
        self.other_public_key=detach1[0]


    def send_message(self, responder):
        message=[]
        if (self.nonce==None):
            message.append(self.id)
            self.nonce=random.randint(1, 100)
            message.append(self.nonce)
        else:
            message.append(self.nonce+1)
            self.nonce = random.randint(1, 100)
            message.append(self.nonce)

        attach1=attach(message)
        encrypted_message=encrypt(self.other_public_key,attach1)
        responder.message=encrypted_message

    def receive_message(self,pkda,responder):
        message=decrypt(self.private_key,self.message)
        detach1=detach(message)
        if (isinstance(detach1[0], str)):
            self.request_public_key(pkda,detach1[0])
            self.nonce=detach1[1]

        if(isinstance(detach1[0],int)):
            if(detach1[0]==self.nonce+1):
                self.nonce=detach1[1]
                self.confirm_send(responder)
    def confirm_send(self,responder):
        message=self.nonce+1
        encrypt_message=encrypt(self.other_public_key,str(message))
        responder.message=encrypt_message
    def confrim(self):
        decrypt1=decrypt(self.private_key,self.message)
        detach1=detach(decrypt1)
        if(self.nonce+1==detach1[0]):
            print("Connection Established")

    def send(self,message,recipient):
        if(self.other_id!=recipient.id):
            print("Don't have recipient Public key contact PKDA")
            return
        message=encrypt(self.other_public_key,message)
        recipient.inbox=message
        print("Messsage: " + str(message) + " sent to " + recipient.id)

    def recieve(self):
        if (self.inbox==None):
            print("Don't have any message")
            return
        message=decrypt(self.private_key,self.inbox)
        print("Messsage: "+message+" recieved at"+self.id)
        self.inbox=None

def simulate_msg(client_a,client_b):
    client_a.send("(Hello from client A)",client_b)
    client_b.recieve()
    client_b.send("(Hello from client B)", client_a)
    client_a.recieve()
    client_a.send("(Hi2)", client_b)
    client_b.recieve()
    client_b.send("(Got2)", client_a)
    client_a.recieve()
    client_a.send("(Hi3)", client_b)
    client_b.recieve()
    client_b.send("(Get3)", client_a)
    client_a.recieve()


# Main flow
pkda = PKDA()

# Client A and B registration
client_a = Client("A",pkda.public_key)
client_b = Client("B",pkda.public_key)

pkda.register_client('A', client_a.public_key)
pkda.register_client('B', client_b.public_key)

simulate(pkda,client_a,client_b)
simulate_msg(client_a,client_b)

client_c= Client("C",pkda.public_key)
simulate_msg(client_a,client_c)