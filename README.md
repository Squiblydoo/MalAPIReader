# MalAPIReader
Reads and prints information from the website [MalAPI.io](https://malapi.io/)

``` 
optional arguments:
  -h, --help            show this help message and exit
  --pe PE, -p PE        Specify a PE to read. The WinAPI will be checked against MalAPI and information will be printed about the API if the information is present.
  --look LOOK, -l LOOK  Look up an API by name and print all information.
  --verbose, -v         Increase verbosity of output
  --report, -r          Write report to the reports directory
  --live LIVE           Use data live on the site rather than stored data. Requires one argument 'y'
```
# New! Local Storage capability.
In this version, the default behavior is to use a locally stored database with the contents of the [MalAPI.io](https://malapi.io/) website. The website was scrapped and saved using shelve. There is currently no functionality to update the database. Users can still use the old functionality of scraping the website by using the `--live` flag, just note that this is remarkably slower.

The locally stored database stores all the metadata from MalAPI though not all of it is visible in MalAPIReader.

There are two utility programs added: MalDictionaryMaker.py and ReadStorage.py
- MalDictionaryMaker.py - I first used HTTTrack to scrape the MalAPI.io website. This utility can then make it into a dictionary for use by MalAPIReader.
- ReadStorage.py - At the current time, this script gives an example of indexing into a dictionary. This script will be modified into a tool for maniputating the contents of the dictionary more effectively. The goal is to have a tool that can easily update or expand descriptions.

# Usage

  The primary option is the --pe option. This option has one required argument: the path and name to an PE file. It will then read the Import Address Table and check for any entries in the local MalAPI.io database (or check the live website, if the optional `--live` option is used. If an entry is found, information about each API is then printed.
  
  For example, in the below image, the binary regsrv.exe1.malz was scanned and information regarding the WinAPI was printed. The output is categorized by API usage type as categorized on MalAPI.io.
![Screen Shot 2022-06-11 at 9 06 26 AM](https://user-images.githubusercontent.com/77356206/173189283-b9f4a463-e423-4e20-9a64-399e5c92f9d5.png)



  The --look option takes one argument: the name of an API. It will then make a request for the basic details about the API from MalAPI.io and print it. In the example below, we pass "GetDesktopWindow" as an argument and receive information back.
![Screen Shot 2022-06-11 at 9 07 03 AM](https://user-images.githubusercontent.com/77356206/173189292-1e48b438-317e-4be8-9b3c-3a096f6f6cfb.png)


# Things to Come
I am planning on improving the output in cases when MalAPIReader throws up or does not have much to say. For example, .NET binaries return little information and I would like to inform the user as to why. Other edge cases are trying to be accounted for too: such as when a binary's import table cannot be handled by MalAPIReader.

I am planning on better highlighting the most interesting imports and providing more guidance to the user.

# Known Bug
Keyboard Interrupts are not reliable. I am able to interrupt when running from IDLE but not when running from cmd.exe


# Thanks
Thank you mr.d0x for the inspiring project.
