import idaapi

def resolve_n_comment(func, func_name):
    """
    Resolve API
    """

    for xref in XrefsTo(LocByName(func_name)):
        # init retrieve arguments
        val1_ea = search_inst(xref.frm, "mov", "edx")
        val1_op = GetOperandValue(val1_ea, 1)
        val2_ea = search_inst(PrevHead(val1_ea), "mov", "ecx")
        val2_op = GetOperandValue(val2_ea, 1)

        # Call Dridex's func
        try:
                addr = func(val1_op, val2_op)
        except:
            continue

        try:
            # Get exported names of all loaded modules
            names = idaapi.get_debug_names(idaapi.cvar.inf.minEA, idaapi.cvar.inf.maxEA)
            # Add comments
            MakeComm(xref.frm, "{:}".format(names[addr].replace("_", "!"))) 
        except:
            continue

def search_inst(ea, inst, op0=None):
    """
    Find first instruction before the given ea
    """
    while True:
        if GetMnem(ea) == inst:
            if op0 and GetOpnd(ea, 0) == op0:
                return ea
        ea = PrevHead(ea)

# Initialization ------------------------------------------
FUNC_NAME = "resolve_api"
PROTO = "PVOID __usercall {:s}@<eax>(DWORD val1@<edx>, DWORD val2@<ecx>);".format(FUNC_NAME)


# Execution -----------------------------------------------
resolve_function = Appcall.proto(FUNC_NAME, PROTO)
resolve_n_comment(resolve_function, FUNC_NAME)
