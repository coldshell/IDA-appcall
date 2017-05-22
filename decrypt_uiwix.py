 def decrypt_n_comment(func, func_name):
    """
    Decryption of UIWIX strings
    """
    for xref in XrefsTo(LocByName(func_name)):
        # init retrieve arguments
        dst_ea = search_inst(xref.frm, "mov")
        dst_op = GetOperandValue(dst_ea, 1)
        src_ea =  PrevHead(dst_ea)
        src_op = GetOperandValue(src_ea, 1)
        buf = Appcall.buffer("\x00" * 256)

        # Call UIWIX func
        try:
            func(buf, src_op)
            res = "{:s}".format(buf.value.decode("utf-8").rstrip('\x00\x00'))
        except:
            continue

        # Add comments
        MakeComm(xref.frm, res) 

def search_inst(ea, inst):
    """
    Find first instruction before the given ea
    """
    while True:
        if GetMnem(ea) == inst:
            return ea
        ea = PrevHead(ea)

# Initialization ------------------------------------------
FUNC_NAME = "get_string"
PROTO = "int __usercall {:s}@<eax>(char* dst@<eax>, char* src@<edx>);".format(FUNC_NAME)

# Execution -----------------------------------------------
decrypt_function = Appcall.proto(FUNC_NAME, PROTO)
decrypt_n_comment(decrypt_function, FUNC_NAME)
