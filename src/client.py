import socket
import sys
import pickle
import threading
import time
import os
import codecs
from datetime import datetime

from encryption import AES, RSA
from requests import *
from constants import *


class Client:
	def __init__(self, username, password):
		self.username = username
		self.password = password

		self.socket = None
		self.closed = False
		self.content = None

		self.target_id = None
		self.target_msg_thread = []

		self.load_all_data()
		self.load_keys()

		self.login(('localhost', 8080))

	def login(self, server_address: tuple):
		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.connect(server_address)

		self.id = ClientID(self.username, RSA.to_string(self.public_key))

		self.s_thread = threading.Thread(target=self.send_thread)
		self.r_thread = threading.Thread(target=self.receive_thread)

		self.s_thread.start()
		self.r_thread.start()

	def load_all_data(self):
		try:
			with open('activity.log', 'r') as f:
				self.log = AES.decrypt(f.read(), self.password).split('\n')
		except:
			self.log = []

		self.conversations = {}
		for file in os.listdir('./saves'):
			if file.endswith('.chat'):
				actual_name = AES.decrypt(file[:-5], self.password)
				with open(f'./saves/{file}', 'r') as f:
					unencrypted_convo = AES.decrypt(f.read(), password)
					
					# Converts str to bytes so it can be unpickled
					self.conversations[actual_name] = pickle.loads(codecs.decode(unencrypted_convo.encode(), "base64"))

	def save_convo(self, target_username, msg_thread):
		file_name = AES.encrypt(target_username, self.password)
		content = codecs.encode(pickle.dumps(msg_thread), "base64").decode()
		encrypted_content = AES.encrypt(content, self.password)

		with open(f'./saves/{file_name}.chat', 'w') as f:
			f.write(encrypted_content)

	def add_log(self, message):
		time_str = datetime.now().strftime("%m/%d/%Y | %H:%M:%S | ")
		self.log.append(time_str + message)
		with open('activity.log', 'w') as f:
			log_content = '\n'.join(self.log)
			f.write(AES.encrypt(log_content, self.password))

	def load_keys(self):
		# Private/Public Keys
		password = bytes(self.password, 'utf-8')
		try:
			self.private_key, self.public_key = RSA.load('key.pem', password)
		except:
			self.private_key, self.public_key = RSA.generate_keys()

			RSA.save(self.private_key, password)

		# Login Secret
		try:
			with open('login_secret.pem', 'r') as f:
				self.login_secret = f.read()
		except:
			self.login_secret = os.urandom(32).hex()

			with open('login_secret.pem', 'w') as f:
				f.write(self.login_secret)

	def create_message(self, content: str) -> Message:
		key = AES.generate_key()

		enc_content = bytes(AES.encrypt(content, key), 'utf-8')

		target_public_key = RSA.from_string(self.target_id.public_key)

		enc_key = RSA.encrypt(key, target_public_key)

		content_sig = RSA.sign(enc_content, self.private_key)
		key_sig = RSA.sign(enc_key, self.private_key)

		message = Message(enc_content, enc_key, content_sig, key_sig)
		request = Response(self.id, self.target_id, 'Message', message)

		return request

	def execute_message(self):
		message = self.create_message(self.content)
		res = Response(self.id, self.target_id, 'Message', message)

		self.socket.send(pickle.dumps(res))
		self.content = None

	def receive_message(self, response: Response):
		message = response.payload

		loaded_public_key = RSA.from_string(response.sender.public_key)

		# Passed verification measures
		if RSA.verify(message.content, message.content_sig, loaded_public_key) and \
				RSA.verify(message.key, message.key_sig, loaded_public_key):
			pass
		# Failed verification
		else:
			return None

		aes_key = RSA.decrypt(message.key, self.private_key)

		decrypted_content = AES.decrypt(message.content, aes_key)

		sys.stdout.write(f"\r[{response.sender.username}] {decrypted_content}\n")
		sys.stdout.write("[Me] ")
		sys.stdout.flush()

	def send_thread(self):
		for line in sys.stdin:
			line = line[:-1] # Removes trailing newline

			# Check for target
			need_target = self.target_id == None

			if need_target:
				sys.stdout.write("Enter user: ")
				sys.stdout.flush()
			else:
				sys.stdout.write("[Me] ")
				sys.stdout.flush()

			if line == "quit":
				self.terminate()
				return
			elif line == "leave":
				self.target_id = None
				continue

			if need_target:
				id_request = Request(self.id, None, 'Id', line)
				self.socket.send(pickle.dumps(id_request))
			else:
				self.content = line
				self.execute_message()
	
	def receive_thread(self):
		while True:

			if self.closed:
				return

			try:
				data_bytes = self.socket.recv(BUFSIZ)
				data = pickle.loads(data_bytes)
			except:
				continue

			if type(data) == Request:
				# Setup request
				if data.header == 'Login':
					self.target_id = data.sender

					secret = self.create_message(self.login_secret)
					res = Response(self.id, self.target_id, 'Login', secret)

					self.socket.send(pickle.dumps(res))
					self.target_id = None

			elif type(data) == Response:
				if data.header == 'Message':
					self.receive_message(data.payload)
				elif data.header == 'Id':
					self.target_id = data.payload
					self.execute_message()

	def terminate(self):
		self.closed = True
		self.socket.close()

		exit()
	


if __name__ == "__main__":
	username = input('Enter your username: ')
	password = input('Enter your password: ')

	client = Client(username, password)