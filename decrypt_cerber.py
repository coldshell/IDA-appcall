def decrypt_n_comment(func, func_name):
    """
    Decryption of cerber string
    """
    for xref in XrefsTo(LocByName(func_name)):
        # init retrieve arguments
        string_ea = search_inst(xref.frm, "push")
        string_op = GetOperandValue(string_ea,0)
        size_ea = search_inst(PrevHead(string_ea), "push")
        size_op = GetOperandValue(size_ea,0)
        key_ea = search_inst(PrevHead(size_ea), "push")
        key_op = GetOperandValue(key_ea,0)

        # Call cerber's func
        try:
            res = func(string_op, size_op, key_op, 1)
        except:
            continue

        # Refresh the memory for GetString function
        idc.RefreshDebuggerMemory()

        try:
            # Add comments
            MakeComm(string_ea, "key[0x{:X}] : '{:s}'".format(key_op, GetString(res,-1,ASCSTR_UNICODE))) 
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
FUNC_NAME = "get_string"
PROTO = "int __cdecl {:s}(PCHAR string, DWORD size, DWORD key, BOOL is_widechar);".format(FUNC_NAME)


# Execution -----------------------------------------------
decrypt_function = Appcall.proto(FUNC_NAME, PROTO)
decrypt_n_comment(decrypt_function, FUNC_NAME)

