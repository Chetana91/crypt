#!/usr/bin/env python

import binascii
import hashlib
import json
import base64
import os

from Crypto.Cipher import AES

''' Global Variables '''
BLOCK_SIZE = 16

PADDING = lambda s: str(BLOCK_SIZE - len(s) % BLOCK_SIZE)

#add padding according to length
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING(s)

#encode/decode with AES
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e))#.rstrip(PADDING(s))

class Crypt():

	def hex_md5(self, string, is_hex):
		m = hashlib.md5()
		if is_hex:
			m.update(string.decode('hex'))
		else:
			m.update(string)
		return m.hexdigest()

	def set_crypt_params(self, bin_key, IV):
		self.master_key = bin_key
		self.IV = IV
		self.decryptor = AES.new(self.master_key, AES.MODE_CBC, self.IV)

	def aes_decrypt(self, bin_text):
		return self.decryptor.decrypt(bin_text)

	def bin_to_int(self, binary_string):
		return int(binary_string.encode('hex'),16)

	def read_database(self, path, input_password):
		self.plaintext = "{"
		try:
			with open(path, "rb") as f:
				magic_number = f.read(4)
				print "Magic Number:", magic_number.encode('hex')

				salt = f.read(4)
				print "Salt:", salt

				IV = f.read(16)
				print "IV:", IV.encode('hex')

				master_key = salt+'$'+input_password
				#print "Master Key:",master_key,",length:", len(master_key)
				bin_key = self.hex_md5(master_key, False).decode('hex')
				print "Binary Key:",bin_key, "length:",len(bin_key)

				self.set_crypt_params(bin_key, IV)

				#next 64 to be decrypted to get MD5

				bin_text = f.read(64)
				#print "Next 64(binary):", bin_text
				print "Next 64(hex):", bin_text.encode('hex')

				bin_text = self.aes_decrypt(bin_text)
				print "* Decrypted text (bin):", bin_text, "length:", len(bin_text)
				hex_text = bin_text.encode('hex')
				print "* Decrypted text (hex):", hex_text, "length:", len(hex_text)

				#extract 32 byte random string, MD5 digest and zeros!
				random_str = hex_text[:64]
				print random_str
				md5 = hex_text[64:-32]
				#zeros = hex_text[-32:]
				print md5
				random_str_md5 = self.hex_md5(random_str, True)
				print random_str_md5
				if random_str_md5 == md5:
					print "Match found"
					#reading next lines
					while True:
						bin_key = f.read(4)
						if len(bin_key)>0:
							key_length = self.bin_to_int(bin_key)
							#print key_length
							key = f.read(key_length)
							print "Key:", key
							self.plaintext = self.plaintext + "\"" + key + "\" : "
							value_length = self.bin_to_int(f.read(4))
							#print value_length
							value = f.read(value_length)
							decrypted_value = self.aes_decrypt(value)#.decode('unicode-escape')
							if decrypted_value[-2:] == decrypted_value[-4:-2]:
								decrypted_value = decrypted_value.rstrip(decrypted_value[-2:])
							print "Value:", decrypted_value, "length:", len(decrypted_value)
							self.plaintext = self.plaintext + decrypted_value + ", "

							#TODO
							f.read(16)
						else:
							print("File Read Complete")
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
				salt = "wYl0".decode('ascii')
				f.write(salt)

			with open(path, "rb") as f:
				magic_number = f.read(4)
				print "Magic Number:", magic_number, len(magic_number)#.encode('hex')
				salt = f.read(4)
				print "Salt:", salt
		except Exception,e:
			print str(e)
		return None
		


def main():
	crypt = Crypt()
	plaintext = crypt.read_database("../demo.db", "uberpass")
	print "Plaintext:", plaintext
	json_text = json.loads(plaintext)
	#other_text = " {\"and\": [\"so\", \"is\", \"nested\", \"data\"], \"is\": \"cool: \u2603\u2744\u2746\"} "
	#print other_text
	#json_text = json.loads (other_text)
	print json_text["is"]

	crypt.write_database("output.db", "uberpass", None)

if __name__ == '__main__':
	main()