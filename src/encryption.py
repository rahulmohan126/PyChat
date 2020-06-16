from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from Crypto.Cipher import AES as aes
from Crypto import Random

import random
import base64
import hashlib
import os
import binascii

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

class AES:
	@staticmethod
	def generate_key():
		chars = '+=/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
		cipher_key = ''.join([random.choice(chars) for i in range(BLOCK_SIZE)])
		return cipher_key

	@staticmethod
	def encrypt(content, key):
		private_key = hashlib.sha256(key.encode("utf-8")).digest()
		content = pad(content)
		iv = Random.new().read(aes.block_size)
		cipher = aes.new(private_key, aes.MODE_CBC, iv)
		return base64.b64encode(iv + cipher.encrypt(bytes(content, 'utf-8'))).decode('utf-8')

	@staticmethod
	def decrypt(content, key):
		private_key = hashlib.sha256(key).digest()
		content = base64.b64decode(content)
		iv = content[:BLOCK_SIZE]
		cipher = aes.new(private_key, aes.MODE_CBC, iv)
		return unpad(cipher.decrypt(content[BLOCK_SIZE:])).decode('utf-8')


class RSA:
	@staticmethod
	def generate_keys():
		private_key = rsa.generate_private_key(
			public_exponent=65537,
			key_size=2048,
			backend=default_backend()
		)

		public_key = private_key.public_key()

		return private_key, public_key

	@staticmethod
	def encrypt(content, public_key):
		return public_key.encrypt(bytes(content, 'utf-8'), padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		))

	@staticmethod
	def decrypt(content, private_key):
		return private_key.decrypt(content, padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		))

	@staticmethod
	def sign(content, private_key):
		return private_key.sign(
			content,
			padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH),
			hashes.SHA256())

	@staticmethod
	def verify(content, signature, public_key):
		try:
			public_key.verify(
				signature,
				content,
				padding.PSS(
					mgf=padding.MGF1(hashes.SHA256()),
					salt_length=padding.PSS.MAX_LENGTH),
				hashes.SHA256())
			return True
		except:
			return False

	@staticmethod
	def load(file_name, password):
		with open(file_name, "rb") as key_file:
			private_key = serialization.load_pem_private_key(
				key_file.read(),
				password=password,
				backend=default_backend()
			)

		public_key = private_key.public_key()

		return private_key, public_key
	
	@staticmethod
	def from_string(string):
		public_key = serialization.load_pem_public_key(
				string,
				backend=default_backend()
			)
		return public_key
	
	@staticmethod
	def to_string(public_key):
		pem = public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)

		return pem

	@staticmethod
	def save(private_key, password, file_name='key.pem'):
		pem = private_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.BestAvailableEncryption(password)
		)

		with open(file_name, 'wb') as f:
			f.write(pem)
