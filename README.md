# MalAPIReader
Reads and prints information from the website MalAPI.io

``` 
optional arguments:
  z -h, --help            show this help message and exit
  --pe PE, -p PE        Specify a PE to read. The WinAPI will be checked
                        against MalAPI and information will be printed about
                        the API if the information is present.
  --look LOOK, -l LOOK  Look up an API by name and print all information.
```
  
  The --look option takes one argument: the name of an API. It will then make a request for the basic details about the API from MalAPI.io and print it.
  
  The --pe option takes one argument: the path and name to an PE file. It will then read the Import Address Table and check for any entries on MalAPI.io. If an entry is found, information about the API is then printed.
  
