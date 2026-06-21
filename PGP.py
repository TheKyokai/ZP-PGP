import base64
import hashlib
import json
import time
import zlib


from Crypto.Cipher import CAST, AES

from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from secrets import token_bytes


class PGP:

    def __init__(self):
        self.private_key_ring = []
        self.public_key_ring = []
        self.load_key_rings()

    def send_message(self, message, options, filename):
        full_msg = "--MESSAGE CONTENTS--\n" + message + "\n--MESSAGE CONTENTS END--"

        # Signing
        if options["sign"]:
            signature = self.generate_signature(message, options)
            if signature is None:
                return False
            signature_info = f"--SIG INFO--\nKEY_ID:{signature["KeyID"]}\nSIG:{signature["signature"]}\n--SIG INFO END--\n"
            full_msg = signature_info + full_msg

        # Compression and UTF-8 encoding
        if options["zip"]:
            full_msg = zlib.compress(full_msg.encode("utf-8"))
        else:
            full_msg = full_msg.encode("utf-8")

        # Encryption
        session_key = None
        initial_value = None
        if options["encrypt"]:
            full_msg, session_key, initial_value = self.encrypt_message(full_msg, options)

        # Packing metadata
        packet_info = "--PACKET INFO--\n"
        if options["radix64"]:
            packet_info += "\nENCODING:RADIX64\n"
        else:
            packet_info += "\nENCODING:BINARY\n"

        if options["sign"]:
            packet_info += "\nSIGNED:Yes\n"
        else:
            packet_info += "\nSIGNED:No\n"

        if options["encrypt"]:
            packet_info += "\nENCRYPTED:Yes\n"
            packet_info += f"KEY_ID:{options['enc_public_key']}\n"
            packet_info += f"ALG:{options['enc_algorithm']}\n"
            packet_info += "MODE:CBC\n"
            packet_info += f"ENCRYPTED_SESSION_KEY:{session_key}\n"
            packet_info += f"IV:{initial_value}\n"
        else:
            packet_info += "\nENCRYPTED:No\n"

        if options["zip"]:
            packet_info += "\nZIPPED:Yes\n"
        else:
            packet_info += "\nZIPPED:No\n"
        packet_info += "\n--PACKET INFO END--\n"

        # TODO Pazi na kodovanje kad citas (Radix64 -> ASCII, Binary)
        # RADIX64 Conversion
        if options["radix64"]:
            full_msg = base64.b64encode(full_msg).decode("ascii")
            with open(filename, 'w') as out_file:
                out_file.write('PGP-R64\n') # Magic first line
                out_file.write(packet_info)
                out_file.write(full_msg)
        else:
            with open(filename, 'wb') as out_file:
                out_file.write(b'PGP-BIN\n') # Magic first line
                out_file.write(packet_info.encode("ascii")) # Encoded header
                out_file.write(full_msg)
        return True



    def generate_signature(self, message, options):
        digest = hashlib.sha1(message.encode("utf-8")).digest()

        pk_row = None
        for row in self.private_key_ring:
            if row["KeyID"] == options["sign_key"]:
                pk_row = row
                break
        if pk_row is None:
            raise Exception

        password_hash = hashlib.sha1(options["sign_key_password"].encode("utf-8")).digest()
        cast_key = password_hash[0:16]

        cast_cipher = CAST.new(cast_key, CAST.MODE_ECB)
        try:
            rsa_private_key_bytes = unpad(cast_cipher.decrypt(pk_row["EncPrivateKey"]), CAST.block_size)
        except ValueError:
            print("Incorrect password - noticed due to unpadding issue")
            return None

        rsa_private_key = RSA.importKey(rsa_private_key_bytes)

        signature = pow(int.from_bytes(digest), rsa_private_key.d, rsa_private_key.n)
        return {"signature": signature, "KeyID": options["sign_key"]}

    def encrypt_message(self, message_bytes, options):
        public_row = None
        for item in self.public_key_ring:
            if item["KeyID"] == options["enc_public_key"]:
                public_row = item
                break

        if public_row is None:
            raise Exception("Public key does not exist")

        session_key = token_bytes(16)
        rsa_public_key = RSA.importKey(public_row["PublicKey"])
        enc_session_key = pow(int.from_bytes(session_key), rsa_public_key.e, rsa_public_key.n)


        initial_value = None
        enc_message = None
        if options['enc_algorithm'] == "CAST5":
            initial_value = token_bytes(CAST.block_size)
            cipher = CAST.new(session_key, CAST.MODE_CBC, initial_value)
            enc_message = cipher.encrypt(pad(message_bytes, CAST.block_size))
        elif options['enc_algorithm'] == "AES128":
            initial_value = token_bytes(AES.block_size)
            cipher = AES.new(session_key, AES.MODE_CBC, initial_value)
            enc_message = cipher.encrypt(pad(message_bytes, AES.block_size))
        else:
            raise Exception("Unknown encryption algorithm")


        return enc_message, enc_session_key.to_bytes((enc_session_key.bit_length() + 7) // 8), initial_value



    # TODO
    def receive_message(self, message):
        pass


    def generate_key_pair(self, email, password, length):
        key_pair = RSA.generate(length)

        timestamp = int(time.time())
        key_id = key_pair.n & 0xFFFFFFFFFFFFFFFF
        rsa_public_key = key_pair.publickey().exportKey()

        rsa_private_key_bytes = key_pair.export_key()
        password_hash = hashlib.sha1(password.encode("utf-8")).digest()
        cast_key = password_hash[0:16]

        cast_cipher = CAST.new(cast_key, CAST.MODE_ECB)
        enc_private_key = cast_cipher.encrypt(pad(rsa_private_key_bytes, CAST.block_size))

        private_key_row = {
            "Timestamp": timestamp,
            "KeyID": key_id,
            "PublicKey": rsa_public_key,
            "EncPrivateKey": enc_private_key,
            "UserID": email
        }

        public_key_row = {
            "Timestamp": timestamp,
            "KeyID": key_id,
            "PublicKey": rsa_public_key,
            "UserID": email
        }

        self.private_key_ring.append(private_key_row)
        self.public_key_ring.append(public_key_row)

        return private_key_row, public_key_row


    def load_key_rings(self, filename=".key_storage.json"):
        with open(filename, "r") as f:
            try:
                data = json.load(f)
            except json.decoder.JSONDecodeError:
                return

        self.private_key_ring = []
        self.public_key_ring = []



        for item in data["private_key_ring"]:
            self.private_key_ring.append({
                "Timestamp": item["Timestamp"],
                "KeyID": item["KeyID"],
                "UserID": item["UserID"],
                "PublicKey": base64.b64decode(item["PublicKey"]),
                "EncPrivateKey": base64.b64decode(item["EncPrivateKey"])
            })

        for item in data["public_key_ring"]:
            self.public_key_ring.append({
                "Timestamp": item["Timestamp"],
                "KeyID": item["KeyID"],
                "UserID": item["UserID"],
                "PublicKey": base64.b64decode(item["PublicKey"])
            })

    def save_key_rings(self, filename=".key_storage.json"):
        data = {
            "private_key_ring": [],
            "public_key_ring": []
        }

        for item in self.private_key_ring:
            data["private_key_ring"].append({
                "Timestamp": item["Timestamp"],
                "KeyID": item["KeyID"],
                "UserID": item["UserID"],
                "PublicKey": base64.b64encode(
                    item["PublicKey"] if isinstance(item["PublicKey"], bytes)
                    else str(item["PublicKey"]).encode()
                ).decode(),
                "EncPrivateKey": base64.b64encode(item["EncPrivateKey"]).decode()
            })

        for item in self.public_key_ring:
            data["public_key_ring"].append({
                "Timestamp": item["Timestamp"],
                "KeyID": item["KeyID"],
                "UserID": item["UserID"],
                "PublicKey": base64.b64encode(
                    item["PublicKey"] if isinstance(item["PublicKey"], bytes)
                    else str(item["PublicKey"]).encode()
                ).decode()
            })

        with open(filename, "w") as f:
            f.write(json.dumps(data, indent=4))



if __name__ == "__main__":
    pgp = PGP()

    private_row, public_row = pgp.generate_key_pair(email="dule@gmail.com", password="Lozinkica", length=1024)
    pgp.send_message("ima žaba",
                     {
                         "sign": False,
                         "sign_key": private_row["KeyID"],
                         "sign_key_password": "Lozinkica",
                         "encrypt": True,
                         "enc_public_key": private_row["KeyID"],
                         "enc_algorithm": "AES128",
                         "zip": False,
                         "radix64": True}, "test.pgp")

