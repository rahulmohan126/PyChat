import time
from datetime import datetime

class ClientID:
	def __init__(self, username, public_key):
		self.username = username
		self.public_key = public_key


class Request:
	def __init__(self, sender, receiver, header, payload):
		self.sender = sender
		self.receiver = receiver
		self.header = header
		self.payload = payload


class Response:
	def __init__(self, sender, receiver, header, payload):
		self.sender = sender
		self.receiver = receiver
		self.header = header
		self.payload = payload


class Message:
	def __init__(self, content : bytes, key : bytes, content_sig : bytes, key_sig : bytes):
		self.content = content
		self.key = key
		self.content_sig = content_sig
		self.key_sig = key_sig
		self.time = datetime.now().strftime("%m/%d/%y %H:%M:%S | ")
