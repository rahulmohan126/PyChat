import socket
import sys
import pickle
import threading
import time

from encryption import AES, RSA
from requests import *
from constants import *

class Server:
	def __init__(self, password):
		self.load_keys(password)
		self.running = True
		self.socket = None
		self.database = self.load_database()
		self.threads = []
		self.message_backup = {} # For messages assigned to users you are not online.

		self.setup()
	
	def load_keys(self, password):
		password = bytes(password, 'utf-8')
		try:
			self.private_key, self.public_key = RSA.load('server.pem', password)
		except:
			self.private_key, self.public_key = RSA.generate_keys()

			RSA.save(self.private_key, password, 'server.pem')

	# Import database of users. The database mainly prevents impersonation through
	# the login secret.
	def load_database(self):
		try:
			with open('db.pkl', 'wb') as f:
				return pickle.load(f)
		except:
			return {}

	# Exports login secrets for all users on database
	def save_database(self):
		export_db = {}

		for username, data in self.database.items():
			
			export_db[username] = {
				'id': data['id'],
				'login_secret': data['login_secret'],
				'online': False
			}
			
		with open('db.pkl', 'wb') as f:
			pickle.dump(export_db, f)

	# Setups up socket
	def setup(self):
		# Socket setup
		ADDR = ('localhost', 8080)

		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.bind(ADDR)
		self.socket.listen(5)

		# ID
		self.id = ClientID('server', RSA.to_string(self.public_key))

		# Start listening for users
		accept_thread = threading.Thread(target=self.accept_incoming_connections)
		accept_thread.start()

	# Creates a socket for all clients attempting to connect
	def accept_incoming_connections(self):
		print("Waiting for connections...")

		while self.running:
			client, client_address = self.socket.accept()
			ip = "%s:%s" % client_address

			print("%s has connected." % ip)

			# Generates a client thread
			client_thread = threading.Thread(target=self.handle_client, args=(ip, client,))

			self.threads.append(client_thread)
			
			client_thread.start()

	# Inputs a response and outputs the login secret within the message
	def extract_secret(self, response: Response):
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

		return decrypted_content
	
	# Handles the client
	def handle_client(self, address, client):
		id_request = Request(self.id, None, 'Login', None)
		client.send(pickle.dumps(id_request))

		client_id = None

		while self.running:
			try:
				data_bytes = client.recv(BUFSIZ)
				data = pickle.loads(data_bytes)
			except:
				client.close()
				self.database[client_id.username]['online'] = False
				print('%s disconnected' % address)
				return

			if type(data) == Response:
				# If no receiver, the response is send to the server
				if data.header == 'Login':
					login_secret = self.extract_secret(data.payload)

					if login_secret == None:
						return

					if data.sender.username not in self.database:
						self.database[data.sender.username] = {
							'socket': client,
							'id': data.sender,
							'login_secret': login_secret,
							'online': True
						}

						client_id = self.database[data.sender.username]['id']
					elif login_secret == self.database[data.sender.username]['login_secret']:
						# Update database with new socket and ip address
						self.database[data.sender.username] = {
							'socket': client,
							'id': data.sender,
							'login_secret': login_secret,
							'online': True
						}

						client_id = self.database[data.sender.username]['id']

						# Login successful, sending any waiting messages (if any)
						if client_id.username in self.message_backup:
							# To ensure that messages are handled properly, some
							# delay is added.
							for msg in self.message_backup[client_id.username]:
								client.send(msg)
								time.sleep(0.2)

							del self.message_backup[client_id.username]
					else:
						return
				elif data.header == 'Message':
					# Carry messages from the sender to the receiver, server ignores
					# messages to non-existant users.
					target_username = data.receiver.username
					if target_username in self.database:
						if self.database[target_username]['online']:
							self.database[target_username]['socket'].send(data_bytes)
						else:
							# Add to message backup if the user is not online.
							if target_username in self.message_backup:
								self.message_backup[target_username].append(data_bytes)
							else:
								self.message_backup[target_username] = [data_bytes]
			elif type(data) == Request:
				# Retrieves the id of any user on the network (username and public key)
				if data.header == 'Id':
					target_username = data.payload
					if target_username in self.database:
						target_id = self.database[target_username]['id']

						res = Response(None, client_id, 'Id', target_id)
						client.send(pickle.dumps(res))
					# Server doesn't respond to requests for non-existant users

		del self.clients[address]

	def terminate(self):
		for username in self.database:
			self.database[username]['socket'].close()
		
		self.running = Falsex

		# self.socket.close()
		self.save_database()


if __name__ == "__main__":
	server = Server('server_password')

	# accept_thread.join()
	
	for line in sys.stdin:
			if line == "quit\n":
				server.terminate()
				exit(0)
