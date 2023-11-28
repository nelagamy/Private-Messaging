import os
import pickle
import string
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

class MessengerServer:
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key


    def decryptReport(self, ct):
        #raise Exception("not implemented!")
        report = self.CCA_Secure_ElGamal_DEC(ct)
        #convert the report into string
        report = report.decode('utf-8')
        return report

    def signCert(self, cert):
        #raise Exception("not implemented!")
        # Serialize the certificate to bytes
        #cert_bytes = pickle.dumps(cert)
        signed_cert = self.server_signing_key.sign(cert, ec.ECDSA(hashes.SHA256()))
        return signed_cert
    
    def CCA_Secure_ElGamal_DEC(self, ELGamal_output):
        #raise Exception("not implemented!")
        # ELGamal_output = (U, C)
        # V = U^server_decryption_key 
        V = self.server_decryption_key.exchange(ec.ECDH(), ELGamal_output[0])
        # K = H(U,V)
        h = hashes.Hash(hashes.SHA256())
        U_byte = ELGamal_output[0].public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        h.update(U_byte)
        h.update(V)
        K = h.finalize()
        # message = D(K, C)
        aesgcm = AESGCM(K)
        fixed_nonce = b'MyFixedNonce' 
        message = aesgcm.decrypt(fixed_nonce, ELGamal_output[1], None)
        return message

    
class Certificate:
    def __init__(self, user_name, public_key):
        self.user_name = user_name
        self.public_key = public_key
        

class ConnectionState:
    def __init__(self):
        self.DHs= None
        self.DHr = None
        self.RK= None
        self.CKs = None
        self.CKr = None
        self.mk = None

class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns = {}
        self.certs = {}
        self.shared_secret = {}
        self.my_initial_pair = self.GENERATE_DH()

    def createConnection(self, name):
        if name not in self.conns:
            self.conns[name] = ConnectionState()

    def generateCertificate(self):
        #raise Exception("not implemented!")
        #convert the public key to bytes
        public_key_bytes = self.my_initial_pair[1].public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        # Generating the certificate
        cert = Certificate(self.name, public_key_bytes)
        cert_bytes = pickle.dumps(cert)
        return cert_bytes

    def receiveCertificate(self, certificate, signature):
        #raise Exception("not implemented!")
        # Verify the certificate
        self.server_signing_pk.verify(signature, certificate, ec.ECDSA(hashes.SHA256()))
        # Store the certificate
        orig_cert = pickle.loads(certificate)
        self.certs[orig_cert.user_name] = orig_cert
        # create your shared secret key with the owner's certificate
        shared_secret = self.DH(self.my_initial_pair, self.prepare_pub_key(orig_cert))
        # store in the shared_secret dictionary
        self.shared_secret[orig_cert.user_name] = shared_secret
        return

    def sendMessage(self, name, message):
        if name not in self.conns:
            self.createConnection(name)
            self.conns[name].RK = self.shared_secret[name]
            self.conns[name].RK, self.conns[name].CKs = self.KDF_RK(self.conns[name].RK,  self.conns[name].RK)
            self.conns[name].CKs, self.conns[name].mk = self.KDF_CK(self.conns[name].CKs)
            message_byte = message.encode('utf-8')
            public_key_bytes = self.my_initial_pair[1].public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            enc_out = self.Encrypt(self.conns[name].mk, message_byte, public_key_bytes)
            self.conns[name].DHs = self.my_initial_pair
            header = self.conns[name].DHs[1]
            return header, enc_out
        else:
            self.conns[name].CKs, self.conns[name].mk = self.KDF_CK(self.conns[name].CKs)
            message_byte = message.encode('utf-8')
            public_key_bytes = self.conns[name].DHs[1].public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            enc_out = self.Encrypt(self.conns[name].mk, message_byte, public_key_bytes)
            header = self.conns[name].DHs[1]
            return header, enc_out
        
    def receiveMessage(self, name, header, ciphertext):
        # Setup the session if not set
        if (name not in self.conns):
            self.createConnection(name)
            self.conns[name].RK = self.shared_secret[name]
            self.conns[name].DHr = header
            self.conns[name].RK, self.conns[name].CKr = self.KDF_RK(self.conns[name].RK, self.conns[name].RK)
            self.conns[name].DHs = self.GENERATE_DH()
            self.conns[name].RK, self.conns[name].CKs = self.KDF_RK(self.conns[name].RK, self.DH(self.conns[name].DHs, self.conns[name].DHr))
            self.conns[name].CKr, self.conns[name].mk = self.KDF_CK(self.conns[name].CKr)
            public_key_bytes = header.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            try:
                plaintext = self.Decrypt(self.conns[name].mk, ciphertext, public_key_bytes)
            except Exception:
                return None
            plaintext = plaintext.decode('utf-8')
            return plaintext
        else:
            if self.conns[name].DHr != header:
                #print("first")
                self.conns[name].DHr = header
                self.conns[name].RK, self.conns[name].CKr = self.KDF_RK(self.conns[name].RK, self.DH(self.conns[name].DHs, self.conns[name].DHr))
                self.conns[name].DHs = self.GENERATE_DH()
                self.conns[name].RK, self.conns[name].CKs = self.KDF_RK(self.conns[name].RK, self.DH(self.conns[name].DHs, self.conns[name].DHr))
                self.conns[name].CKr, self.conns[name].mk = self.KDF_CK(self.conns[name].CKr)
                public_key_bytes = header.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                try:
                    plaintext = self.Decrypt(self.conns[name].mk, ciphertext, public_key_bytes)
                except Exception:
                    return None
                plaintext = plaintext.decode('utf-8')
                return plaintext

            if self.conns[name].DHr == header:
                self.conns[name].CKr, self.conns[name].mk = self.KDF_CK(self.conns[name].CKr)
                public_key_bytes = header.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                try:
                    plaintext = self.Decrypt(self.conns[name].mk, ciphertext, public_key_bytes)
                except Exception:
                    return None
                plaintext = plaintext.decode('utf-8')
                return plaintext
            
    def report(self, name, message):
        #raise Exception("not implemented!")
        report = name + "," + message
        encrypted_report = self.CCA_Secure_ElGamal_ENC(report)
        return report, encrypted_report
    
    def GENERATE_DH(self):
        # Generate a private key for use in the exchange.
        private_key = ec.generate_private_key(ec.SECP256R1())
        # Generate a public key for use in the exchange.
        public_key = private_key.public_key()
        dh_pair = (private_key, public_key)
        return dh_pair
    
    def DH(self, dh_pair, dh_pub):
        dh_out = dh_pair[0].exchange(ec.ECDH(), dh_pub)
        return dh_out
    
    def KDF_RK(self, rk, dh_out):
        # Ratchet DH Keys
        out = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=rk,
            info=b'handshake data',
        ).derive(dh_out)
        rk = out[:32]
        ck = out[32:]
        return (rk, ck)
    
    def KDF_CK(self, ck):
        # 32-byte message key
        h_m = hmac.HMAC(ck, hashes.SHA256())
        h_m.update (b'0x01')
        m_k = h_m.finalize()
        # 32-byte chain key
        h_c = hmac.HMAC(ck, hashes.SHA256())
        h_c.update(b'0x02')
        m_c = h_c.finalize()
        return (m_c, m_k)
    
    def Encrypt(self, m_k, plaintext, header):
        aesgcm = AESGCM(m_k)
        fixed_nonce = b'MyFixedNonce' 
        ct = aesgcm.encrypt(fixed_nonce, plaintext, header)
        return ct
    
    def Decrypt(self, m_k, ct, header):
        aesgcm = AESGCM(m_k)
        fixed_nonce = b'MyFixedNonce' 
        plaintext = aesgcm.decrypt(fixed_nonce, ct, header)
        return plaintext
    
    def CCA_Secure_ElGamal_ENC(self, report):
        #raise Exception("not implemented!")
        #convert the report into bytes
        report_bytes = report.encode('utf-8')
        # Generate the private key y
        y = ec.generate_private_key(ec.SECP256R1())
        # U = g^y
        U = y.public_key()
        # V = self.server_encryption_pk^y
        V = y.exchange(ec.ECDH(), self.server_encryption_pk)   
        # K = H(U,V)
        h = hashes.Hash(hashes.SHA256())
        #change U and V to bytes  
        U_byte = U.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        h.update(U_byte)
        h.update(V)
        K = h.finalize()
        # C = E(K, message)
        aesgcm = AESGCM(K)
        fixed_nonce = b'MyFixedNonce' 
        C = aesgcm.encrypt(fixed_nonce, report_bytes, None)
        # Output (U,C)
        ELGamal_output = (U, C)
        return ELGamal_output

    def prepare_pub_key(self, cert):
        pub_key = serialization.load_pem_public_key(cert.public_key, backend=None)
        return pub_key


    

    







    
        

