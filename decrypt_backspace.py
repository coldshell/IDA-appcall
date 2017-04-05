import re

def decrypt_n_comment(func, func_name):
    """
    Decryption of backspace string
    """
    for xref in XrefsTo(LocByName(func_name)):
        # init retrieve arguments
        string_ea = search_inst(xref.frm, "push")
        string_op = GetOperandValue(string_ea,0)
        size_op = len("{}".format(GetString(string_op,-1, ASCSTR_C)))

        # Call backspace's func
        try:
            func(string_op, size_op)
            res = "{:s}".format(GetString(string_op,-1, ASCSTR_C))
        except:
            continue

        # Refresh the memory for GetString function
        idc.RefreshDebuggerMemory()

        try:
            # Add comments
            MakeComm(xref.frm, res) 
            # Patch strings and names
            idaapi.put_many_bytes(string_op, res)
            MakeName(string_op, re.sub('\W+','', res))
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
PROTO = "int __cdecl {:s}(PCHAR strings, DWORD size);".format(FUNC_NAME)

# Execution -----------------------------------------------
decrypt_function = Appcall.proto(FUNC_NAME, PROTO)
decrypt_n_comment(decrypt_function, FUNC_NAME)
