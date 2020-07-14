#Finds all VTables, prints them out in the console
#@author Magnus "Nopey" Larsen
#@category 
#@keybinding 
#@menupath Tools.Misc.Find all VTables
#@toolbar 
program = getCurrentProgram()
symbol_table = program.getSymbolTable()

symbols = symbol_table.getSymbolIterator()
monitor.initialize(symbol_table.getNumSymbols())
for symbol in symbols:
    monitor.checkCanceled()
    # TV for VTables, _Z prefix for all external symbols.
    # https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling-special-vtables
    if symbol.getName().startswith("__ZTV"):
        print symbol
    monitor.incrementProgress(1)
