import rsa
import hashlib
from datetime import datetime, timedelta

def create_hash(certificate):
    # Concatenate the components of the certificate
    concatenated_string = (
            certificate.issuer +
            certificate.id +
            certificate.date_issued +
            certificate.validity +
            str(certificate.publickey)
    )

    # Calculate the hash value of the concatenated string using SHA-256
    hash_value = hashlib.sha256(concatenated_string.encode()).hexdigest()

    return hash_value


def verify_certificate(certificate, public_key):
    # Recreate the hash of the certificate as it was when signed
    certificate_hash = create_hash(certificate)

    # Verify the signature
    try:
        rsa.verify(certificate_hash.encode(), certificate.signature, public_key)
        return True
    except rsa.VerificationError:
        return False
def verify_time(certificate, secpassed):
    # Display debugging information
    print("Date Issued (Time):", certificate.date_issued)
    print("Validity (Seconds):", certificate.validity)
    print("Seconds Passed:", secpassed)

    # Current time adjusted by seconds passed
    current_time = datetime.now() + timedelta(seconds=secpassed)

    # Date Issued Time, considering today's date combined with the time from the certificate
    time_of_issue = datetime.strptime(certificate.date_issued, "%H:%M:%S").time()
    date_issued = datetime.combine(datetime.today(), time_of_issue)

    # Calculate expiry time by adding validity period to the date issued
    validity_seconds = int(certificate.validity)
    expiry_time = date_issued + timedelta(seconds=validity_seconds)

    # Print out times for debugging
    print("Date Issued (Full):", date_issued.time())
    print("Current Time:", current_time.time())
    print("Expiry Time:", expiry_time.time())

    # Check if the current adjusted time is within the validity period
    return date_issued.time() <= current_time.time() <= expiry_time.time()

class Certificate:
    def __init__(self, issuer, id, date_issued, validity,publickey):
        self.issuer = issuer
        self.id = id
        self.date_issued = date_issued
        self.validity = validity
        self.publickey=publickey
        self.signature=None

class Transport_Office:
    def __init__(self, office_id, public_key, private_key):
        self.id = office_id
        self.public_key = public_key
        self.private_key = private_key
        self.public_keys_map = {}
    def register_office(self,Regional_office):
        self.public_keys_map[Regional_office.id] = Regional_office.public_key
        Regional_office.Transport_Office=self
        print(f"Regional office {Regional_office.id} registered with Transport Office {self.id}")
    def get_certificate(self,id):
        date_issued =datetime.now().strftime("%H:%M:%S")
        validity = "1000"
        c=Certificate(self.id,id,date_issued,validity,self.public_keys_map[id])
        certificate_hash = create_hash(c)
        signature = rsa.sign(certificate_hash.encode('utf-8'), self.private_key, 'SHA-256')
        c.signature = signature
        return c


class Regional_Office:
    def __init__(self, office_id, public_key, private_key):
        self.id = office_id
        self.public_key = public_key
        self.private_key = private_key
        self.public_keys_map = {}
        self.Transport_Office=None
    def get_certificate(self,id):
        if id not in self.public_keys_map:
            c=self.Transport_Office.get_certificate(id)
            verify1=verify_certificate(c,self.Transport_Office.public_key)
            verify2=verify_time(c,10)
            if(verify1 and verify2):
                print("Certificate Received  from",self.Transport_Office.id, "is Verified and Valid")
            elif (verify1):
                print("Certificate Received  from", self.Transport_Office.id, "is Verified but not Valid")
            else:
                print("Certificate Received  from", self.Transport_Office.id, "is not Verified & Valid")
            self.public_keys_map[c.id]=c.publickey
        date_issued=datetime.now().strftime("%H:%M:%S")
        validity="1000"

        c = Certificate(self.id, id, date_issued, validity, self.public_keys_map[id])
        certificate_hash = create_hash(c)
        signature = rsa.sign(certificate_hash.encode('utf-8'), self.private_key, 'SHA-256')
        c.signature = signature

        return c
    def make_certificate(self,Driver):
        date_issued = datetime.now().strftime("%H:%M:%S")
        validity ="100"
        c= Certificate(self.id, Driver.id, date_issued, validity, Driver.public_key)
        certificate_hash = create_hash(c)
        signature = rsa.sign(certificate_hash.encode('utf-8'), self.private_key, 'SHA-256')
        c.signature = signature
        Driver.Certificate=c

class Driver:
    def __init__(self,id, public_key, private_key):
        self.Certificate=None
        self.Certificate=None
        self.id = id
        self.public_key = public_key
        self.private_key = private_key


class Officer:
    def __init__(self,ro):
        self.public_keys_map = {}
        self.Regional_Office=ro
    def verify(self, certificate,time):

        # Extract information from the certificate object

        issuer_public_key = certificate.issuer
        if issuer_public_key  not in self.public_keys_map:
            c=self.Regional_Office.get_certificate(certificate.issuer)
            verify1 = verify_certificate(c, self.Regional_Office.public_key)

            verify2 = verify_time(c, 10)
            if (verify1 and verify2):
                print("Certificate Received  from", self.Regional_Office.id, "is Verified and Valid")
            elif (verify1):
                print("Certificate Received  from", self.Regional_Office.id, "is Verified but not Valid")
            else:
                print("Certificate Received  from", self.Regional_Office.id, "is noy Verified & Valid")
            self.public_keys_map[c.id] = c.publickey
        verify1=verify_certificate(certificate,self.public_keys_map[issuer_public_key])
        verify2 = verify_time(certificate,time)

        if (verify1 and verify2):
            print("Certificate Received  from Driver is Verified and Valid")
        elif (verify1):
            print("Certificate Received  from Driver is Verified but not Valid")
        else:
            print("Certificate Received  from Driver is not Verified & Valid")


#Transport Office Keys
public_key_T, private_key_T= rsa.newkeys(1000)
public_key_RA, private_key_RA= rsa.newkeys(1000)
public_key_RB, private_key_RB= rsa.newkeys(1000)

T=Transport_Office("H",public_key_T,private_key_T)
RA=Regional_Office("RA",public_key_RA,private_key_RA)
RB=Regional_Office("RB",public_key_RB,private_key_RB)
T.register_office(RA)
T.register_office(RB)
public_key_D1, private_key_D1= rsa.newkeys(1000)
public_key_D2, private_key_D2= rsa.newkeys(1000)

D1=Driver("A",public_key_D1,private_key_D1)
RA.make_certificate(D1)

D2=Driver("B",public_key_D2,private_key_D2)
RB.make_certificate(D2)
O=Officer(RA)


O.verify(D2.Certificate,10000)
print("----------------------------------------------")
print("----------------------------------------------")
O.verify(D1.Certificate,10)