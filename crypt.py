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
EIGHT = 8

class Crypt():
	#main class defining methods to read and write database

	def pad(self, s):
		result = StringIO.StringIO()
		m = SIXTEEN - (len(s) % SIXTEEN)
		# if m>9:
		# 	hx = '%02x' % m #str(hex(m))
		# else:
		# 	hx = str(m)
		# print "pad:", s + hx*m
		# print "-----" , hx
		# return s + hx*m

		for _ in xrange(m):
			result.write('%02x' % m)
		print "-----" , m, result.getvalue()
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

	def int_to_bytearray(self, int_val):

		b_str = '{0:032b}'.format(int_val)
		bit_strings = [b_str[i:i + 8] for i in range(0, len(b_str), 8)]
		byte_list = [int(b, 2) for b in bit_strings]
		return bytearray(byte_list)

		# bytes = bin(int_val)
		# print "bytes:",bytes
		# #return bytes


		# #int_val = 10
	 # 	int_bytes = bytearray(4)
	 # 	index = len(str(int_val))
	 # 	print int_val, "index", index
	 # 	#if val_len>4:
		# int_bytes[-index] = int_val
		# return int_bytes

	def read_database(self, path, input_password):
		print "*********** Reading Database ***********"
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
						print "bin_key:", bin_key
						if len(bin_key)>0:
							key_length = self.bin_to_int(bin_key)
							print "key_length", key_length
							key = f.read(key_length)
							print "Key:", key
							self.plaintext = self.plaintext + "\"" + key.rstrip('\x00').decode('unicode-escape') + "\" : "
							value_length = self.bin_to_int(f.read(4))
							print "value_length---", value_length
							value = f.read(value_length)
							print len(value)
							decrypted_value = self.aes_decrypt(value).rstrip('\00\0\1')
							print "****"

							if decrypted_value[-1:] == decrypted_value[-2:-1]:
								decrypted_value = decrypted_value.rstrip(decrypted_value[-1:])
							elif decrypted_value[-1:] == '\x01':
								decrypted_value = decrypted_value.rstrip('\x01')
							print "Value:", decrypted_value, "length:", len(decrypted_value)
							self.plaintext = self.plaintext + decrypted_value.rstrip('\x00').decode('unicode-escape') + ", "

							md5 = f.read(16)
							val_md5 = self.hex_md5(decrypted_value, False)
							if md5 == val_md5:
								print "MD5 Matched"
						else:
							print("File Read Complete")
							break
			return self.plaintext.rstrip(", ")+"}"
		except Exception,e:
			print str(e)
		return None


	#(unicode_text path, unicode_text password, dict contents) -> void
	def write_database(self, path, input_password, contents):
		print "*********** Writing Database ***********"
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

				#print "Master Key:", master_key
				bin_key = self.hex_md5(master_key, False).decode('hex')

				self.set_crypt_params(bin_key, IV)

				# generate a random secret
				secret = os.urandom(THIRTY_TWO)
				secret_md5 = self.md5(secret)
				zeros = ('0'*EIGHT).encode('hex')
				big_secret = secret+secret_md5+zeros
				#print "Big Secret:", big_secret, len(big_secret), len(secret), len(secret_md5), len(zeros)

				encrypted_text = self.aes_encrypt(big_secret)
				#print encrypted_text, len(encrypted_text)
				f.write(encrypted_text)

				#return

				for key in sorted(contents):
					json_value = json.dumps(contents[key], separators=(',', ': '))
					key_length = len(key)
					print "json", key, key_length," || ", json_value , len(json_value)
					byte_key = self.int_to_bytearray(key_length)
					print "byte_key", byte_key, len(byte_key)
					f.write(byte_key)
					f.write(key)
					print key, "---", key_length
					 
					#add padding
					padded_val = self.pad(json_value)
					print "padded_val:", padded_val,"||", len(padded_val)
					#encrypt value
					encrypted_val = self.aes_encrypt(padded_val)
					#f.write(str(len(encrypted_val)))
					val_length = len(encrypted_val)
					byte_val = self.int_to_bytearray(val_length)
					print val_length
					f.write(byte_val)
					f.write(encrypted_val)
					value_md5 = self.md5(json_value)
					f.write(value_md5)

		except Exception,e:
			print str(e)
		return None
		


def main():
	print "*********** This is to test ***********"
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