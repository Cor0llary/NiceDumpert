import sys


file1_b = bytearray(open(sys.argv[1], 'rb').read())
file2_b = bytes([0x4B])		# xor key


size = len(file1_b)
xord_byte_array = bytearray(size)


for i in range(size):
	xord_byte_array[i] = file1_b[i] ^ file2_b[0]


open(sys.argv[2], 'wb').write(xord_byte_array)

print("[*] %s XOR %s\n[*] Saved to \033[1;33m%s\033[1;m."%(sys.argv[1], file2_b, sys.argv[2]))
