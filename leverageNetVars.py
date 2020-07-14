# Fill struct fields that are netvars
#@author Magnus "Nopey" Larsen
#@category 
#@keybinding 
#@menupath Tools.Misc.Leverage Netvars
#@toolbar 
# SAD POINT: DOESN'T HANDLE ARRAYS ELEGANTLY
#TODO: What does InsideArray flag mean?

import re#gex
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.data import PointerDataType, Pointer
from ghidra.program.database.data import StructureDB
program = getCurrentProgram()
dataManager = program.getDataTypeManager()
fm = program.getFunctionManager()
program_name = program.getName()

# all_datatypes is just a way of skipping the paths from the DataTypeManager
# (degenerate, I know ;)
all_datatypes = dict()
for d in dataManager.getAllDataTypes():
    all_datatypes[d.getName()] = d

# ASK SECTION
netvars_txt = "/home/magnus/proj/ghidra/netprops.txt"
# netvars_txt = askString("Leverage NetVars", "Path to dumped netprops.txt")
is_client = "client" in program_name

# from https://csrd.science/misc/datadump/5830736.7z
netvars_file = open(netvars_txt)
lines = netvars_file.readlines()
class_name = None # ex: "CAI_BaseNPC"
class_struct = None
trail = dict() # the parent tables
monitor.initialize(len(lines))
for line in lines:
    monitor.checkCanceled()
    line = line.rstrip()
    expression = line.lstrip()
    indentation = len(line) - len(expression)
    if indentation==0:
        class_name = line.split()[0]
        if is_client and class_name[0]=="C":
            class_name = "C_" + class_name[1:]
        monitor.setMessage("Laying Out: " + class_name)
        class_struct = all_datatypes.get(class_name)
        # print(class_name)
        if class_struct is None:
            print("WARNING: class {} not found".format(class_name))
    elif expression.startswith("Table:"):
        # Table: AnimTimeMustBeFirst (offset 0) (type DT_AnimTimeMustBeFirst)
        split = expression.split()
        table = split[1]
        offset = int(split[3][:-1])
        if table == "baseclass":
            table = None
        trail[indentation] = (table, offset)
    elif expression.startswith("Member:"):
        if class_struct is not None:
            # Member: m_flAnimTime (offset 148) (type integer) (bits 8) (Unsigned|ChangesOften)
            split = expression.split()
            end_name = split[1]
            offset = int(split[3][:-1])
            field_type = split[5][:-1]
            bits = int(split[7][:-1])
            unsigned = "Unsigned" in expression
            
            # for some reason Pikachu's CSRD doesn't handle VectorXY properly
            # and just prints the enum value: 3
            field_data_type = None
            field_size = None
            if field_type=="3" or field_type=="vector":
                field_data_type = dataManager.getDataType(program_name + "/Demangler/Vector")
                field_size = 12
            elif field_type=="integer":
                if bits <= 8:
                    # C chars are signed. bytes are unsigned.
                    field_data_type = dataManager.getDataType("/byte" if unsigned else "/char")
                    field_size = 1
                elif bits <= 16:
                    field_data_type = dataManager.getDataType("/ushort" if unsigned else "/short")
                    field_size = 2
                elif bits <= 32:
                    field_data_type = dataManager.getDataType("/uint" if unsigned else "/int")
                    field_size = 4
                else:
                    print("ERROR! integer has too many bits! ({})".format(bits))
            elif field_type=="float":
                # TODO: Might some floats not be 32bit?
                field_data_type = dataManager.getDataType("/float")
                field_size = 4
            elif field_type=="string":
                # TODO: Is this just plain wrong?
                field_data_type = PointerDataType(dataManager.getDataType("/TerminatedCString"))
                field_size = 4
            elif field_type=="array":
                print("SKIPPING array type for field {} of {}".format(field_name, class_name))
                continue
            else:
                print("ERROR! unknown type ({})".format(field_type))

            # Use the trail to build up the offset and field_name
            field_name = ""
            field_offset = offset
            for i in range(1, indentation):
                name, offset = trail[i]
                if name is not None:
                    field_name = field_name + name + "_"
                field_offset += offset
            field_name = field_name + end_name

            class_struct.insertAtOffset(field_offset, field_data_type, field_size, field_name, "")
            burn = field_size
            burnAt = field_offset + field_size
            while field_size>0:
                at = class_struct.getComponentAt(burnAt)
                if at is None:
                    break
                at_len = at.getLength()
                class_struct.deleteAtOffset(burnAt)
                burn   -= at_len
                burnAt -= at_len
            while field_size<0:
                print("WARN: Partially overwrote preexisting field on {}".format(class_name))
                class_struct.insertAtOffset(burnAt, dataManager.getDataType("/undefined1"), 1, "", "")
            # print("[{}] {}: {}".format(field_offset, field_name, field_data_type.getName(), field_size))
            # break
    elif len(expression)==0:
        # empty lines are cool
        pass
    else:
        print("I don't understand this line: \'{}\'".format(expression))

    monitor.incrementProgress(1)