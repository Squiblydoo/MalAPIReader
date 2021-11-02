import pefile
import requests
import bs4
import argparse

parser = argparse.ArgumentParser(description="Read information from MalAPI.io for WinAPI information.")
parser.add_argument("--pe", "-p", help="Specify a PE to read. The WinAPI will be checked against MalAPI and information will be printed about the API if the information is present.")
parser.add_argument("--look", "-l", help="Look up an API by name and print all information.")
args = parser.parse_args()

def apiCheck(api):
    APItoCheck = api
    APICheck = requests.get("https://malapi.io/winapi/" + APItoCheck)
    APICheck.raise_for_status()
    APISoup = bs4.BeautifulSoup(APICheck.text, 'html.parser')
    details = APISoup.select('.detail-container .content')
    ApiInfo = details[1].getText().lstrip().rstrip()
    print("--->", ApiInfo)


# Lookpup an individual API by name
if (args.look):
    apiCheck(args.look)

# Read read import table from PE and print information when it is found.
elif (args.pe):
    print(args.pe)
    pe = pefile.PE(args.pe, fast_load=True)
    pe.parse_data_directories()
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print("----", entry.dll.decode("utf-8"),"----")
        for imp in entry.imports:
            print(imp.name.decode("utf-8"))
            try:
                apiCheck(imp.name.decode("utf-8"))
            except:
                continue
    print("If an API listed here was used maliciously, but its use was not listed, consider contributing information to MalAPI.io.")
            
    
