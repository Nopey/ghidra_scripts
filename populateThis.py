#Automatically fill struct fields
#@author Magnus "Nopey" Larsen
#@category 
#@keybinding 
#@menupath Tools.Misc.Populate empty structs
#@toolbar 


import re#gex
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.data import PointerDataType, Pointer
from ghidra.program.database.data import StructureDB
program = getCurrentProgram()
dataManager = program.getDataTypeManager()
# We use the decompiler to find accesses to fields.
ifc = DecompInterface()
ifc.openProgram(program)
fm = program.getFunctionManager()

# all_datatypes is just a way of skipping the paths from the DataTypeManager
all_datatypes = dict()
for d in dataManager.getAllDataTypes():
    all_datatypes[d.getName()] = d
all_datatypes["code"] = all_datatypes["void"]

def getAddress(offset):
	return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

def strToDataType(s):
    """
    Converts a C-Style type like `uint` or `CTFPlayer *` to a Ghidra DataType
    """
    indirection = 0
    while s[-1]=='*':
        s = s[:-1]
        indirection+=1
    s = s.rstrip()
    t = all_datatypes.get(s, all_datatypes['undefined1'])
    for i in range(0,indirection):
        t = PointerDataType(t)
    return t

def scoreDataTypeStr(s):
    """
    Gives a score to type, like `uint` or `uint *`.
    These scores are used to prioritize some types over others.
    """
    score = 0
    if s.startswith("undefined"):
        score = 0
    elif s.startswith("byte"):
        score = 1
    elif s.startswith("char"):
        score = 2
    elif s.startswith("ushort"):
        score = 3
    elif s.startswith("short"):
        score = 4
    elif s.startswith("uint"):
        score = 5
    elif s.startswith("int"):
        score = 6
    elif s.startswith("float"):
        score = 7
    elif s.startswith("double"):
        score = 8
    elif s.startswith("code"):
        score = 9
    else:
        # probably a StructureDataType
        if s in all_datatypes:
            score = 10
        else:
            # undefined
            score = 0

    # Pointers are godly.
    while s[-1]=='*':
        s = s[:-1]
        score+=100

    return score

# A record of observations, such as CTFPlayer-> (16, "uint") "I saw a uint at offset 16 of CTFPlayer"
records = dict()

def observe_function(func):
    # decompile the function and print the pseudo C
    results = ifc.decompileFunction(func, 0, ConsoleTaskMonitor())
    decomp_func = results.getDecompiledFunction()
    if decomp_func is None:
        # No decompilation available
        print("Failed to decompile {} ({})".format(func.getName(), func))
        return
    c_code = decomp_func.getC()
    # print(c_code)

    for param in func.getParameters():
        data_type = param.getDataType()
        try:
            data_type = data_type.getDataType()
        except Exception as e:
            # We only care about pointers
            return

        # We don't care about builtins
        if type(data_type) is not StructureDB:
            return

        observation_list = records.get(data_type, list())

        # Look for accesses into the 'this' ptr.
        # NOTE: This properly skips the vtable (1st field), because there's no ptr offset.

        # *(float *)(this + 0xc40)
        regex = '\*\((\w+ \*+)\)\({} \+ ((0x[0-9a-f]+)|(\d+))\)'
        regex = regex.format(param.getName())
        regex = re.compile(regex)
        for match in regex.finditer(c_code):
            field_type = match.group(1)
            field_offset = int(match.group(2), 0)
            # print("{0}[{2}]: {1}".format(data_type.getName(),field_type, field_offset))
            observation_list.append((field_offset, field_type[:-1].rstrip()))

        # (byte)param_1[0x6c]
        regex = '\((\w+ ?\**)\){}\[((0x[0-9a-f]+)|(\d+))\]'
        regex = regex.format(param.getName())
        regex = re.compile(regex)
        for match in regex.finditer(c_code):
            field_type = match.group(1)
            field_offset = int(match.group(2), 0)
            # print("{0}[{2}]: {1}".format(data_type.getName(),field_type, field_offset))
            observation_list.append((field_offset, field_type))

        # Record what offset and type was used.
        records[data_type] = observation_list

# '''
# Get all the functions in the program, and prepare the progress bar
funcs = list(fm.getFunctions(True)) # True means 'forward'
monitor.initialize(len(funcs))
print "Inspecting functions.."

for func in funcs:
    monitor.checkCanceled()
    monitor.setMessage("Observe: " + func.getName())

    observe_function(func)

    monitor.incrementProgress(1)
# '''

# observe_function(fm.getFunctionContaining(getAddress(3731440)))

records = records.items()
monitor.initialize(len(records))
for data_type, observations in records:
    monitor.checkCanceled()
    # Skip ones that are predefined or manually written.
    if not data_type.isNotYetDefined:
        continue

    monitor.setMessage("Layout: " + data_type.getName())
    layout = dict()
    for o in observations:
        (field_offset, field_type) = o
        prev = layout.get(field_offset)
        score = scoreDataTypeStr(field_type)
        if prev is not None:
            if prev[1]>score:
                continue
        layout[field_offset] = (field_type, score)

    # This second loop inserts fields into Ghidra's DataType Manager 
    #   from the lowest offset field to the highest offset field
    #   to ensure that fields never overlap.
    #
    # the minimum offset for the next field
    min = 0
    # Sort the layout, because the dictionary doesn't.
    layout = layout.items() 
    layout.sort()
    for offset, field in layout:
        # Overlap detected, continue.
        if min > offset:
            continue
        # score isn't used down here, but was used while taking the observations.
        # field is a string like `uint` or `code *`
        field, score = field
        field_datatype = strToDataType(field)
        data_type.insertAtOffset(offset, field_datatype, field_datatype.getLength(), "field_{}".format(hex(offset)[2:]), "")
        min = offset + field_datatype.getLength()
    monitor.incrementProgress(1)
