import shelve
from pathlib import Path
import pprint

Storage = Path('.//Storage//MalAPIStorage.dat')
if Storage.exists():
    shelveFile = shelve.open('.//Storage//MalAPIStorage')
    
    for s in sorted(shelveFile.iteritems(), key=lambda  y: y['name']):
        print(s)
    #pprint.pprint(sortlist)
    
    
    shelveFile.close()

