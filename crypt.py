#!/usr/bin/env python

import binascii
import hashlib
import json
import base64
import os
import sys
import StringIO

from Crypto.Cipher import AES

''' Global Variables '''
THIRTY_TWO = 32
SIXTEEN = 16

class Crypt():
	#main class defining methods to read and write database

	def pad(self, s):
		result = StringIO.StringIO()
		m = SIXTEEN - (len(s) % SIXTEEN)
		for _ in xrange(m):
			result.write('%02x' % m)
		return s + binascii.unhexlify(result.getvalue())

	def hex_md5(self, string, is_hex):
		m = hashlib.md5()
		if is_hex:
			m.update(string.decode('hex'))
		else:
			m.update(string)
		return m.hexdigest()

	def md5(self, bin_string):
		m = hashlib.md5()
		m.update(bin_string)
		return m.digest()

	def set_crypt_params(self, bin_key, IV):
		self.master_key = bin_key
		self.IV = IV
		self.cryptor = AES.new(self.master_key, AES.MODE_CBC, self.IV)

	def aes_decrypt(self, bin_text):
		return self.cryptor.encrypt(bin_text)

	def aes_encrypt(self, bin_text):
		return self.cryptor.decrypt(bin_text)

	def bin_to_int(self, binary_string):
		return int(binary_string.encode('hex'),16)

	# 
	def int_to_bytearray(self, int_val):
		b_str = '{0:032b}'.format(int_val)
		bit_strings = [b_str[i:i + 8] for i in range(0, len(b_str), 8)]
		byte_list = [int(b, 2) for b in bit_strings]
		return bytearray(byte_list)

	def read_database(self, path, input_password):
		self.plaintext = "{"
		try:
			with open(path, "rb") as f:
				magic_number = f.read(4)

				salt = f.read(4)

				IV = f.read(16)

				master_key = salt+'$'+input_password
				bin_key = self.hex_md5(master_key, False).decode('hex')

				self.set_crypt_params(bin_key, IV)

				bin_text = f.read(64)

				bin_text = self.aes_decrypt(bin_text)
				hex_text = bin_text.encode('hex')

				#extract 32 byte random string, MD5 digest and zeros!
				random_str = hex_text[:64]
				md5 = hex_text[64:-32]
				random_str_md5 = self.hex_md5(random_str, True)
				if random_str_md5 == md5:
					#reading key-value pairs
					while True:
						bin_key = f.read(4)
						if len(bin_key)>0:
							key_length = self.bin_to_int(bin_key)
							key = f.read(key_length)
							self.plaintext = self.plaintext + "\"" + key.rstrip('\x00').decode('unicode-escape') + "\" : "
							value_length = self.bin_to_int(f.read(4))
							value = f.read(value_length)
							decrypted_value = self.aes_decrypt(value).rstrip('\00\0\1')

							if decrypted_value[-1:] == decrypted_value[-2:-1]:
								decrypted_value = decrypted_value.rstrip(decrypted_value[-1:])
							elif decrypted_value[-1:] == '\x01':
								decrypted_value = decrypted_value.rstrip('\x01')
							self.plaintext = self.plaintext + decrypted_value.rstrip('\x00').decode('unicode-escape') + ", "

							md5 = f.read(16)
						else:
							break
			return self.plaintext.rstrip(", ")+"}"
		except Exception,e:
			print str(e)
		return None


	#(unicode_text path, unicode_text password, dict contents) -> void
	def write_database(self, path, input_password, contents):
		try:
			with open(path, "wb") as f:
				#writing the default magic number to file
				magic_number = 'badcab00'.decode('hex')
				f.write(magic_number)
				#writing salt characters
				salt = 'wYl0'.decode('ascii')
				f.write(salt)

				#generate IV
				IV = os.urandom(SIXTEEN)
				f.write(IV)

				master_key = salt+'$'+input_password

				bin_key = self.hex_md5(master_key, False).decode('hex')

				self.set_crypt_params(bin_key, IV)

				# generate a random secret
				secret = os.urandom(THIRTY_TWO)
				secret_md5 = self.md5(secret)
				zeros = ('0'*8).encode('hex')
				big_secret = secret+secret_md5+zeros

				encrypted_text = self.aes_encrypt(big_secret)
				f.write(encrypted_text)
				for key in sorted(contents):
					json_value = json.dumps(contents[key], separators=(',', ': '))
					key_length = len(key)
					byte_key = self.int_to_bytearray(key_length)
					f.write(byte_key)
					f.write(key)
					 
					#add padding
					padded_val = self.pad(json_value)
					#encrypt value
					encrypted_val = self.aes_encrypt(padded_val)
					val_length = len(encrypted_val)
					byte_val = self.int_to_bytearray(val_length)
					f.write(byte_val)
					f.write(encrypted_val)
					value_md5 = self.md5(json_value)
					f.write(value_md5)

		except Exception,e:
			print str(e)
		return None

def main():
	crypt = Crypt()
	db = "{\"i am\" : \"reading this\", \"it was\" : \"a fun exercise to find\", \"key\" : \"and value for\", \"uber.com\" : \"is sekret password\", \"unicode\" : {\"and\": [\"so\", \"is\", \"nested\", \"\"], \"data\": \"is cool: \u2603\"}}"
	#db = "{\"are you\" : \"reading this\", \"if so\" : \"good job, because you are half done ish\", \"key\" : \"value\", \"uber.com\" : \"sekret password\", \"unicode\" : {\"and\": [\"so\", \"is\", \"nested\", \"data\"]}}"
	db_dict = json.loads(db)
	crypt.write_database("output.db", "uberpass", db_dict)

	plaintext = crypt.read_database("output.db","uberpass")
	print "Plaintext:", plaintext
	if plaintext is not None:
		json_text = json.loads(plaintext, strict=False)
		if u"uber.com" in json_text:
			print json_text[u"uber.com"]

if __name__ == '__main__':
	main()