#Finds all VTables, prints them out in the console
#@author Magnus "Nopey" Larsen
#@category 
#@keybinding 
#@menupath Tools.Misc.Find all VTables
#@toolbar 
program = getCurrentProgram()
# dataManager = program.getDataTypeManager()
symbol_table = program.getSymbolTable()

symbols = symbol_table.getSymbolIterator()
monitor.initialize(symbol_table.getNumSymbols())
for symbol in symbols:
    monitor.checkCanceled()
    if symbol.getName().startswith("__ZTV"):
        print symbol
    monitor.incrementProgress(1)
