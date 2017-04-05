def decrypt(func):
	"""
	Decryption of all the string in Zeus
	"""
	ZBOT_INDEX_MIN = 0x0
	ZBOT_INDEX_MAX = 0xe7
	data = {}
	
	for i in range(ZBOT_INDEX_MIN, ZBOT_INDEX_MAX):
 
		buf = Appcall.buffer("\x00" * 512)
		# Call the Zbot function
		func(i, buf)
		data[i] = buf.value.decode("utf-16").rstrip('\x00\x00')

	return data

def comment(data, func_name):

	for xref in XrefsTo(LocByName(func_name)):
		# Get previous instruction
		ea = PrevHead(xref.frm)

		# Check for mnemonics
		if GetMnem(ea) == "mov":
			# Get index value
			op = GetOperandValue(ea,1)
		elif "pop" in [GetMnem(ea), GetMnem(PrevHead(ea))]:
			#search for a 'push 0xINDEX'
			while True:
				ea = PrevHead(ea)
				if GetMnem(ea) == "push":
					# Get index value
					op = GetOperandValue(ea,0)
					break
		else:
			continue

                try:
		    # Add comments
		    MakeComm(ea, "index[0x{:X}] : '{:s}'".format(op, data[op])) 
                except:
                    continue

# Initialization ------------------------------------------
FUNC_NAME = "decrypt_data_wide"
PROTO = "void __usercall {:s}(int data_index@<eax>, void *buf@<esi>);".format(FUNC_NAME)


# Execution -----------------------------------------------
decrypt_function = Appcall.proto(FUNC_NAME, PROTO)
comment(decrypt(decrypt_function), FUNC_NAME)
