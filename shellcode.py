import ctypes, struct, numpy, sys
from keystone import *


def print_shellcode(payload):
    
    print("[+] Payload assembly code + coresponding bytes")
    asm_blocks = ""
    prev_size = 0
    for line in payload.splitlines():
        asm_blocks += line + "\n"
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(payload)
        if encoding:
            enc_opcode = ""
            for byte in encoding[prev_size:]:
                enc_opcode += "0x{0:02x} ".format(byte)
                prev_size += 1
            spacer = 30 - len(line)
            print("%s %s %s" % (line, (" " * spacer), enc_opcode))

    final = ""
    final += 'shellcode = b"'

    for enc in encoding:
        final += "\\x{0:02x}".format(enc)

    final += '"'

    print(f"[=] {final[14:-1]}", file=sys.stderr)

def to_hex(s):
    retval = list()
    for char in s:
        retval.append(hex(ord(char)).replace("0x", ""))
    return "".join(retval)

def to_sin_ip(ip_address):
    ip_addr_hex = []
    for block in ip_address.split("."):
        ip_addr_hex.append(format(int(block), "02x"))
    ip_addr_hex.reverse()
    return "0x" + "".join(ip_addr_hex)

def to_sin_port(port):
    port_hex = format(int(port), "04x")
    return "0x" + str(port_hex[2:4]) + str(port_hex[0:2])

def ror_str(byte, count):
	binb = numpy.base_repr(byte, 2).zfill(32)
	while count > 0:
		binb = binb[-1] + binb[0:-1]
		count -= 1
	return (int(binb, 2))

def push_function_hash(function_name):
	edx = 0x00
	ror_count = 0
	for eax in function_name:
		edx = edx + ord(eax)
		if ror_count < len(function_name)-1:
			edx = ror_str(edx, 0xd)
		ror_count += 1
	return ("push " + hex(edx))

def push_string(input_string):
    rev_hex_payload = str(to_hex(input_string))
    rev_hex_payload_len = len(rev_hex_payload)

    instructions = []
    first_instructions = []
    null_terminated = False
    for i in range(rev_hex_payload_len, 0, -1):
        # add every 4 byte (8 chars) to one push statement
        if ((i != 0) and ((i % 8) == 0)):
            target_bytes = rev_hex_payload[i-8:i]
            instructions.append(f"push dword 0x{target_bytes[6:8] + target_bytes[4:6] + target_bytes[2:4] + target_bytes[0:2]};")
        # handle the left ofer instructions
        elif ((0 == i-1) and ((i % 8) != 0) and (rev_hex_payload_len % 8) != 0):
            if (rev_hex_payload_len % 8 == 2):
                first_instructions.append(f"mov al, 0x{rev_hex_payload[(rev_hex_payload_len - (rev_hex_payload_len%8)):]};")
                first_instructions.append("push eax;")
            elif (rev_hex_payload_len % 8 == 4):
                target_bytes = rev_hex_payload[(rev_hex_payload_len - (rev_hex_payload_len%8)):]
                first_instructions.append(f"mov ax, 0x{target_bytes[2:4] + target_bytes[0:2]};")
                first_instructions.append("push eax;")
            else:
                target_bytes = rev_hex_payload[(rev_hex_payload_len - (rev_hex_payload_len%8)):]
                first_instructions.append(f"mov al, 0x{target_bytes[4:6]};")
                first_instructions.append("push eax;")
                first_instructions.append(f"mov ax, 0x{target_bytes[2:4] + target_bytes[0:2]};")
                first_instructions.append("push ax;")
            null_terminated = True
            
    instructions = first_instructions + instructions
    asm_instructions = "".join(instructions)
    return asm_instructions

def shellcode():


    ASM = [
    " start:                             ",  # ASM instruction here
    "   xor eax, eax                    ;",  #   
    ]
    return "\n".join(ASM)


payload = shellcode()

print_shellcode(payload)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(payload)
print("Encoded %d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))

print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
