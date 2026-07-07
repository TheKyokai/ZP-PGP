import ast
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
        full_msg = f"TIMESTAMP:{int(time.time())}\n"
        full_msg += "--MESSAGE CONTENTS--\n" + message + "\n--MESSAGE CONTENTS END--"

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

        rsa_private_key, row = self.decypt_private_key(options["sign_key_password"], options["sign_key"])

        signature = pow(int.from_bytes(digest), rsa_private_key.d, rsa_private_key.n)
        return {"signature": signature, "KeyID": options["sign_key"]}

    def encrypt_message(self, message_bytes, options):
        public_row = self.find_public_row(options["enc_public_key"])

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

    def read_packet_info(self, filename, read_options, ending_line, decode_option):
        options = {}
        with open(filename, read_options) as in_file:
            in_file.readline()
            line = in_file.readline()
            while line != ending_line:
                if decode_option is not None:
                    line = line.decode(decode_option)
                line = line.split(':')
                if len(line) < 2:
                    line = in_file.readline()
                    continue
                options[line[0].lower()] = ':'.join(line[1:]).strip()
                if line[1].strip() == "No":
                    options[line[0].lower()] = False
                elif line[1].strip() == "Yes":
                    options[line[0].lower()] = True
                line = in_file.readline()

            #reads the rest of the file for decrypting
            content = in_file.read()

        return options, content

    def find_public_row(self, keyID):
        public_row = None
        for item in self.public_key_ring:
            if item["KeyID"] == keyID:
                public_row = item
                break

        if public_row is None:
            raise Exception("Public key does not exist")
        return public_row

    def decypt_private_key(self, password, keyID):
        private_row = None
        for item in self.private_key_ring:
            if item["KeyID"] == keyID:
                private_row = item
                break

        if private_row is None:
            raise Exception("Private key does not exist")
        print(f"private row: {private_row}")
        password_hash = hashlib.sha1(password.encode("utf-8")).digest()
        cast_key = password_hash[0:16]
        cast_cipher = CAST.new(cast_key, CAST.MODE_ECB)
        try:
            rsa_private_key = unpad(cast_cipher.decrypt(private_row["EncPrivateKey"]), CAST.block_size)
        except ValueError:
            raise Exception("Incorrect password - noticed due to unpadding issue")

        rsa_private_key = RSA.importKey(rsa_private_key)
        print(f"d = {rsa_private_key.d}")
        print(f"n = {rsa_private_key.n}")

        public_key = RSA.importKey(private_row["PublicKey"])
        print(f"n = {public_key.n}")
        return rsa_private_key, private_row

    def decrypt_message(self, message, options, password):

        #finding the private key for decrypting
        rsa_private_key, row = self.decypt_private_key(password, options["key_id"])

        # now the session key can be decrypted
        enc_session_key = options["encrypted_session_key"]
        e_bytes = ast.literal_eval(enc_session_key)
        enc_session_key = int.from_bytes(e_bytes)
        session_key = pow(enc_session_key, rsa_private_key.d, rsa_private_key.n).to_bytes(length = 16)

        initial_value = ast.literal_eval(options["iv"])
        if options['alg'] == "CAST5":
            cipher = CAST.new(session_key, CAST.MODE_CBC, initial_value)
            dec_message = unpad(cipher.decrypt(message), CAST.block_size)
        elif options['alg'] == "AES128":
            cipher = AES.new(session_key, AES.MODE_CBC, initial_value)
            dec_message = unpad(cipher.decrypt(message), AES.block_size)
        else:
            raise Exception("Unknown encryption algorithm")

        return dec_message

    def verify_signature(self, key_id, signature, content):
        #decrypt the signature and hash the content then compare
        digest = hashlib.sha1(content.encode("utf-8")).digest()
        digest = int.from_bytes(digest)
        pk_row = self.find_public_row(key_id)
        rsa_public_key = RSA.importKey(pk_row["PublicKey"])
        dec_signature = pow(int(signature), rsa_public_key.e, rsa_public_key.n)
        return dec_signature == digest

    def receive_message(self, filename, app):

        with open(filename, 'rb') as in_file:
            # reading first line for encoding
            line = in_file.readline()
            if line == b'PGP-R64\r\n' or line == b'PGP-R64\n':
                 radix64 = True
                 read_option = "r"
                 ending_line = '--PACKET INFO END--\n'
                 decode_option = None
            elif line == b'PGP-BIN\r\n' or line == b'PGP-BIN\n':
                radix64 = False
                read_option = "rb"
                ending_line = b'--PACKET INFO END--\n'
                decode_option = "ascii"
            else:
                raise Exception("Invalid encoding")

        #reading line by line for recreating encrypting options
        options, content = self.read_packet_info(filename, read_option, ending_line, decode_option)

        # Radix read to bytes
        if radix64:
            content = base64.b64decode(content.encode("ascii"))

        #Decryption
        if options["encrypted"]:
            password = app.prompt_password()
            content = self.decrypt_message(content, options, password)

        #unzipping
        if options['zipped']:
            content = zlib.decompress(content)
        content = content.decode("utf-8")

        #signing
        content_rows = content.split("\n")
        verified = None
        #first have to parse for signing options
        if options['signed']:
            key_id = content_rows[1].split(":")[1]
            signature = content_rows[2].split(":")[1]
            timestamp = content_rows[4].split(":")[1]
            content = "\n".join(content_rows[6:-1])
            verified = self.verify_signature(key_id, signature, content)
        else:
            # now reading the timestamp
            timestamp = content.split("\n")[0].split(":")[1]
            content = "\n".join(content_rows[2:-1])
        return content, verified, timestamp

    def generate_key_pair(self, name, email, password, length):
        key_pair = RSA.generate(length)

        timestamp = int(time.time())
        key_id = hex(key_pair.n & 0xFFFFFFFFFFFFFFFF)
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
            "UserEmail": email,
            "Username": name,
            "Length": length
        }

        public_key_row = {
            "Timestamp": timestamp,
            "KeyID": key_id,
            "PublicKey": rsa_public_key,
            "UserID": email,
            "UserEmail": email,
            "Username": name,
            "Length": length
        }

        self.private_key_ring.append(private_key_row)
        self.public_key_ring.append(public_key_row)

        return private_key_row, public_key_row

    # Export and import of keys
    def export_public_key_PEM(self, key_id, filename):
        key_row = self.find_public_row(key_id)
        rsa_public_key = RSA.importKey(key_row["PublicKey"])

        with open(filename, "wb") as f:
            f.write(rsa_public_key.exportKey("PEM"))

    def export_private_key_PEM(self, key_id, filename, password):
        rsa_private_key, row = self.decypt_private_key(password, key_id)

        with open(filename, "wb") as f:
            f.write(rsa_private_key.exportKey("PEM"))

    def import_public_key_PEM(self, key_filename_PEM, username, email):
        if not key_filename_PEM or not username or not email:
            raise Exception("Nedovoljno podataka za uvoz")

        try:
            with open(key_filename_PEM, "rb") as f:
                rsa_key = RSA.import_key(f.read())
        except FileNotFoundError:
            raise Exception("Fajl ne postoji")
        except ValueError or TypeError or IndexError:
            raise Exception("Neispravan format fajla")


        rsa_key.size_in_bits()
        key_id = hex(rsa_key.n & 0xFFFFFFFFFFFFFFFF)

        imported_key = {
            "Timestamp": int(time.time()),
            "KeyID": key_id,
            "UserEmail": email,
            "Username": username,
            "PublicKey": rsa_key.public_key().exportKey(),
            "Length": rsa_key.size_in_bits()
        }

        self.public_key_ring.append(imported_key)

    def import_private_key_PEM(self, key_filename_PEM, username, email, password):
        if not key_filename_PEM or not username or not email or not password:
            raise Exception("Nedovoljno podataka za uvoz")

        try:
            with open(key_filename_PEM, "rb") as f:
                rsa_key = RSA.import_key(f.read())
        except FileNotFoundError:
            raise Exception("Fajl ne postoji")
        except ValueError or TypeError or IndexError:
            raise Exception("Neispravan format fajla")

        if not rsa_key.has_private():
            raise Exception("Fajl sadrži samo javni deo ključa")

        rsa_key.size_in_bits()
        key_id = hex(rsa_key.n & 0xFFFFFFFFFFFFFFFF)

        password_digest = hashlib.sha1(password.encode("utf-8")).digest()
        cast_key = password_digest[0:16]

        cast_cipher = CAST.new(cast_key, CAST.MODE_ECB)
        enc_private_key = cast_cipher.encrypt(pad(rsa_key.exportKey(), CAST.block_size))

        imported_key = {
            "Timestamp": int(time.time()),
            "KeyID": key_id,
            "UserEmail": email,
            "Username": username,
            "PublicKey": rsa_key.public_key().exportKey(),
            "EncPrivateKey": enc_private_key,
            "Length": rsa_key.size_in_bits()
        }

        self.private_key_ring.append(imported_key)

    # Key loading and saving from file
    def load_key_rings(self, filename=".key_storage.json"):
        try:
            with open(filename, "r") as f:
                try:
                    data = json.load(f)
                except json.decoder.JSONDecodeError:
                    return
        except FileNotFoundError:
            return

        self.private_key_ring = []
        self.public_key_ring = []

        for item in data["private_key_ring"]:
            self.private_key_ring.append({
                "Timestamp": item["Timestamp"],
                "KeyID": item["KeyID"],
                "UserEmail": item["UserEmail"],
                "Username": item["Username"],
                "PublicKey": base64.b64decode(item["PublicKey"]),
                "EncPrivateKey": base64.b64decode(item["EncPrivateKey"]),
                "Length": item["Length"]
            })

        for item in data["public_key_ring"]:
            self.public_key_ring.append({
                "Timestamp": item["Timestamp"],
                "KeyID": item["KeyID"],
                "UserEmail": item["UserEmail"],
                "Username": item["Username"],
                "PublicKey": base64.b64decode(item["PublicKey"]),
                "Length": item["Length"]
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
                "UserEmail": item["UserEmail"],
                "Username": item["Username"],
                "PublicKey": base64.b64encode(item["PublicKey"]).decode("ascii"),
                "EncPrivateKey": base64.b64encode(item["EncPrivateKey"]).decode("ascii"),
                "Length": item["Length"]
            })

        for item in self.public_key_ring:
            data["public_key_ring"].append({
                "Timestamp": item["Timestamp"],
                "KeyID": item["KeyID"],
                "UserEmail": item["UserEmail"],
                "Username": item["Username"],
                "PublicKey": base64.b64encode(item["PublicKey"]).decode("ascii"),
                "Length": item["Length"]
            })

        with open(filename, "w") as f:
            f.write(json.dumps(data, indent=4))



if __name__ == "__main__":
    # pgp = PGP()
    # for item in pgp.private_key_ring:
    #     print(item)
    # pgp.export_private_key_PEM(pgp.private_key_ring[0]["KeyID"], "PGP_Files/test_private_export.pem", "a")
    # pgp.import_private_key_PEM("PGP_Files/test_private_export.pem", "test", "test@gmail.com", "abc")
    # print('\n')
    # print(pgp.private_key_ring[0])
    # print(pgp.private_key_ring[len(pgp.private_key_ring) - 1])
    pass

