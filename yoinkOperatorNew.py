# Truncates (and grows) structs to the size that is provided to operator.new
#@author Magnus "Nopey" Larsen
#@category 
#@keybinding 
#@menupath Tools.Misc.Yoink operator new()
#@toolbar

import re#gex
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.database.data import StructureDB
program = getCurrentProgram()
dataManager = program.getDataTypeManager()
fm = program.getFunctionManager()
program_name = program.getName()
refman = program.getReferenceManager()
ifc = DecompInterface()
ifc.openProgram(program)

# all_datatypes is just a way of skipping the paths from the DataTypeManager
# (degenerate, I know ;)
monitor.setMessage("enumerating all types to eliminate namespacing")
all_datatypes = dict()
for d in dataManager.getAllDataTypes():
    all_datatypes[d.getName()] = d

# ASK SECTION
#
is_client = "client" in program_name
# hardcode the addres of operator.new to avoid ambiguity between its overloads
# (I think the overloads are copy-new's?)
op_new_addr = None
if is_client:
    op_new_addr = 0x0042bb40
else:
    op_new_addr = 0x00459280
op_new_addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(op_new_addr)
# op_new_fn = fm.getFunctionAt(op_new_addr)

# A list of functions that have been decompiled and processed already
hit_funcs = set()
# A list of types that have already been allocated, and their size.
hit_types = dict()
# STATS
stat_skip = 0
stat_skip_type = 0
stat_mismatch_size = 0
stat_no_decomp = 0

def truncateDT(data_type, typesize):
    # Step 1. Truncate
    while data_type.getLength() > typesize:
        data_type.deleteAtOffset(typesize)
    # Step 2. Fill with undefined1
    data_type.growStructure(data_type.getSize())

# \(\w+ \*\)operator.new\(((0x[0-9a-f]+)|(\d+))\)
regex = '\\((\\w+) \\*\\)operator.new\\(((0x[0-9a-f]+)|(\\d+))\\)'
regex = re.compile(regex)

monitor.setMessage("enumerating cross refererences to operator.new..")
xrefs = list(refman.getReferencesTo(op_new_addr))

monitor.initialize(len(xrefs))
for xref in xrefs:
    monitor.checkCanceled()
    monitor.setMessage(str(xref))
    # let's find the function that is calling us,
    # and decompile it.
    func = fm.getFunctionContaining(xref.getFromAddress())
    if func is None:
        print( "No function found for xref at address " + str(xref.getFromAddress()))
        continue
    if func in hit_funcs:
        stat_skip += 1
        continue
    hit_funcs.add(func)
    results = ifc.decompileFunction(func, 0, ConsoleTaskMonitor())
    decomp_func = results.getDecompiledFunction()
    if decomp_func is None:
        # No decompilation available
        print("Failed to decompile {} ({})".format(func.getName(), func))
        stat_no_decomp += 1
        continue
    c_code = decomp_func.getC()
    for match in regex.finditer(c_code):
       typename = match.group(1)
       typesize = int(match.group(2), 0)
       hit = hit_types.get(typename)
       if hit is not None:
           stat_skip_type += 1
           if hit != typesize:
               stat_mismatch_size += 1
               print("WARNING: {} size mismatch: {} VS {}".format(typename, hit, typesize))
           continue
       # print(typename, typesize)
       data_type = all_datatypes.get(typename)
       if data_type is None:
           print("Couldn't find data_type '{}'".format(typename))
       elif type(data_type) is not StructureDB:
           pass # we don't care about undefined4 or int allocations
       else:
           hit_types[typename] = typesize
           truncateDT(data_type, typesize)
    monitor.incrementProgress(1)

print("STATS:\nskip {}\nskip type {}\nmismatch {}\ntypes {}\ndecomp fail {}".format(stat_skip, stat_skip_type, stat_mismatch_size, len(hit_types), stat_no_decomp))
