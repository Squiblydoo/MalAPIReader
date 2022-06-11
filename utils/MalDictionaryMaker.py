import os
import bs4
import shelve
from pathlib import Path
import pprint

shelveFile = shelve.open("MalAPIStorage")
MalAPIDictionary = {}

def open_api_file(filename):
    with open(filename, encoding='utf8') as infile:
        return infile.read()

# Iterate through files to make the dictionary
MapAPIDirectory = "C:\\Users\\Karol\\programming\\MalAPIReader\\MapAPIMirror\\MalAPI\\malapi.io\\winapi\\"
for filename in os.listdir(MapAPIDirectory):

    APICheck = open_api_file(MapAPIDirectory + filename)
    APISoup = bs4.BeautifulSoup(APICheck, 'html.parser')

    #API Description
    details = APISoup.select('.detail-container .content')
    ApiInfo = details[1].getText().lstrip().rstrip()

    #Library Info
    ApiLibrary = details[2].getText().lstrip().rstrip()

    #Documentation Info
    MSDocs = details[4].getText().lstrip().rstrip()

    #Get entry metadata
    MetaDataSoup = APISoup.select('.square-box')
    MetaData = MetaDataSoup[0].getText().lstrip().rstrip()

    #Api Associated Attacks
    attackDetails = APISoup.select('.attack-container')
    attackInfo = attackDetails[0].getText().lstrip().rstrip()

    #Make API Dictionary Entry
    APIDetails = {"name": Path(filename).stem, "Description": ApiInfo, "ATT&CK Info": attackInfo, "Library Info": ApiLibrary, "MS Documentation": MSDocs, "Metadata": MetaData}
    MalAPIDictionary[Path(filename).stem] = APIDetails


pprint.pprint(MalAPIDictionary)
shelveFile["API"] = MalAPIDictionary
shelveFile.close