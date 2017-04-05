def decrypt_n_comment(func, func_name, enc):
    """
    Decryption of Satan string
    """
    for xref in XrefsTo(LocByName(func_name)):
        # init retrieve arguments
        index_ea = search_inst(xref.frm, "push")
        index_op = GetOperandValue(index_ea, 0)

        buf = Appcall.buffer("\x00" * 512)

        # Call Satan's func
        res = func(index_op, buf)

        try:
            # Add comments
            MakeComm(xref.frm, "index[0x{:X}] : '{:s}'".format(index_op, buf.value.decode(enc).rstrip('\x00\x00'))) 
        except:
            continue

def search_inst(ea, inst):
    """
    Find first instruction before the given ea
    """
    while True:
        if GetMnem(ea) == inst:
            return ea
        ea = PrevHead(ea)

# Initialization ------------------------------------------
FUNC_NAMEW = "get_stringW"
FUNC_NAMEA = "get_stringA"
PROTO = "int __usercall {:s}@<eax>(WORD index@<ecx>, PCHAR buf@<edx>);".format(FUNC_NAME)


# Execution -----------------------------------------------
decrypt_function = Appcall.proto(FUNC_NAMEW, PROTO)
decrypt_n_comment(decrypt_function, FUNC_NAMEW, "utf-16")

decrypt_function = Appcall.proto(FUNC_NAMEA, PROTO)
decrypt_n_comment(decrypt_function, FUNC_NAMEA, "utf-8")
