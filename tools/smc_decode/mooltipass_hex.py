import Crypto.Util.Counter
import Crypto.Cipher.AES
import json
import sys
import socket

def internet(host="8.8.8.8", port=53, timeout=3):
	"""
	Host: 8.8.8.8 (google-public-dns-a.google.com)
	OpenPort: 53/tcp
	Service: domain (DNS/TCP)
	"""
	try:
		socket.setdefaulttimeout(timeout)
		socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
		return True
	except Exception as ex:
		print ex.message
		return False

if __name__ == '__main__':	

	if internet():
		print "This computer appears to be connected to the internet!"
		print "Is is strongly recommended that this utility is used on an offline pc."
		print "Type \"I understand\" in the following prompt to proceed."    
		text_input = raw_input("Text input: ").rstrip()
		if text_input != "I understand":
			sys.exit(0)	

	# Warning part
	print ""
	print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!  WARNING  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	print "!                                                                                                       !"
	print "! Using this tool effectively renders your Mooltipass useless.                                          !"
	print "! After accepting the following prompt, and entering yout AES key.                                      !"
	print "! Both your credential database and its decryption key will therefore be in your computer memory.       !"
	print "! If your computer is infected, all your logins & passwords can be decrypted without your knowledge.    !"
	print "! Type \"I understand\" in the following prompt to proceed                                              !"
	print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	print "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	text_input = raw_input("Text input: ").rstrip()
	if text_input != "I understand":
		sys.exit(0)

		# Ask the user to enter the path to the JSON file
	print ""
	jsonfile_path = raw_input("Please enter the path to the memory export file: ").rstrip().lstrip('"').rstrip('"')
	with open(jsonfile_path) as json_file:
		json_data = json.load(json_file)
		nonce = []
		for i in range(8, 24):
			nonce.append(json_data[1][0][str(i)])
		nonce_string = ''.join('{:02x}'.format(x) for x in nonce)
		print "Nonce found:", nonce_string.upper()	
        
	aes_key_string_for_func = raw_input("Please enter the AES Key hex: ").rstrip()
	aes_key_string_for_func = aes_key_string_for_func.replace("0x", "").replace(",", "").replace(":", "").replace(" ", "").replace(".", "")
	aes_key_string_for_func = aes_key_string_for_func.rstrip().decode("hex")

	# Loop through service nodes
	print ""
	print "Looping through memory file contents..."
	for i in range(0, len(json_data[5])):
		print "Parent node", json_data[5][i]["name"]	
		# Reconstruct node data
		node_data = []
		for j in range(0, 132):
			node_data.append(json_data[5][i]["data"][str(j)])
			
		child_address = node_data[6:8]
		if child_address[0] == 0 and child_address[1] == 0:
			print "... doesn't have children"
		else:
			# Decrypt children
			while(child_address[0] != 0 or child_address[1] != 0):	
				# Loop through children to find addresses
				for j in range(0, len(json_data[6])):
					# Compare the wanted and actual address
					if json_data[6][j]["address"][0] == child_address[0] and json_data[6][j]["address"][1] == child_address[1]:
						# Rebuild node data
						node_data = []
						for k in range(0, 132):
							node_data.append(json_data[6][j]["data"][str(k)])
						
						# decrypt data
						iv = nonce[:]
						iv[13] ^= node_data[34]
						iv[14] ^= node_data[35]
						iv[15] ^= node_data[36]
						#print "CTR value:", ''.join('{:02x}'.format(x) for x in node_data[34:37])
						#print "IV value:", ''.join('{:02x}'.format(x) for x in iv)
						iv_string = ''.join('{:02x}'.format(x) for x in iv)
						ctr = Crypto.Util.Counter.new(128, initial_value=long(iv_string, 16))		
						cipher = Crypto.Cipher.AES.new(aes_key_string_for_func, Crypto.Cipher.AES.MODE_CTR, counter=ctr)
						password = cipher.decrypt(''.join(chr(x) for x in node_data[100:132]))
						password = password.split("\x00")[0]
						
						# print data
						print "Login:", json_data[6][j]["name"], "password:", password
						child_address = node_data[4:6]
						break