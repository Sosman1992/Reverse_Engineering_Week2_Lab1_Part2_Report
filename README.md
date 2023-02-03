# Week 1 - Simple Static Analysis

The Weeks Lab focus was on the use of file hashes as a technique for identifying malware samples. Additionally, submitted sample of malware files or hashes by uploading these file via Google's VirusTotal website to scan the files with a variety of antivirus programs embedded in the website. Furthermore used BinText GUI  to search for ASCII and Unicode `strings` inside of a binary and also discovered how to use PEiD to determine whether the binary of a malware samples executable or linked library file is compressed to conceal its contents. Lastly exploration of Windows system tools that are used by portable executable including libraries that get dynamically linked and which functions are imported was also learnt.

---
# Lab 1-3 

## Executive Summary

The executable is a malware recognized by virusTotal because it was  file appears to be a packed malware and trying to unpack it with UPX utility tool was not successful. And this can be confirmed by using the PeID utility tool to open the sample and this goes on further to prove that FSG was used in compression of the file. Also opening the file in PEview shows that it is lacking import table and without the import table I am unable to know the functions and linking libraries used by this executable sample when it infects machines or users on a network, Nonetheless, using We open the file with Dependency Walker it shows the import table of this executable with two functions namely `LoadLibrary` and `GetProcAddress` that are always associated with 
Packed files. This further indicate that this file is packed. In conclusion running the sample using the known tools I know for performing static analysis did not provide any useful information for a host-based indicator or network signature, that can serve as the indicators of compromise, and mitigations required for protection from this malware.

## Indicators of Compromise 

**Compilation Date (presumed):** DEC 2010

**MD5 Hash (EXE):** bb7425b82141a1c0f7d60e5106676bb1

**SHA-1 Hash (EXE):**  9dce39ac1bd36d877fdb0025ee88fdaff0627cdb 

**SHA-256 Hash (EXE):**  58898bd42c5bd3bf9b1389f0eee5b39cd59180e8370eb9ea838a0b327bd6fe47 

**MD5 Hash (DLL):** 290934c61de9176ad682ffdd65f0a669 

**SHA-1 Hash (DLL):**  a4b35de71ca20fe776dc72d12fb2886736f43c22 

**SHA-256 Hash (DLL):** f50e42c8dfaab649bde0398867e930b86c2a599e8db83b8260393082268f2dba

**File to look for:** `C:\windows\system32\kerne132.dll`

**File type:** Win32 DLL 


## Mitigations

- Deletions of files matching any of these hashes obtained from the scanning result from the VirusTotal website
- Scan Windows machines for `system32\kerne132.dll`

## Evidence

The malware is a portable executable (EXE) and uploading it to VirusTotal antivirus engine sets off dozens of vendors' virus classifiers.

Opening the file with PEiD indicates that these files were written and compiled using Microsoft Visual C++ 6.0 , we see that they both claim to have been compiled in late 2010. 

Opening the `.EXE` in BinText, the message string "`WARNING_THIS_WILL_DESTROY_YOUR_MACHINE`", and some other suspicious string "`C:\windows\system32\kerne132.dll`", which replaces the `l` in kernel with a `1`. Nonetheless, windows does not have a file named `kerne132.dll` hence the presence of such serves to be a proof that of malware availability.

Opening these files with PEview, it can be seen that they both claim to have been compiled in late 2010. This matches what VirusTotal reported, but VirusTotal only saw samples appear in mid-2012.

Using Dependency Walker on the `.DLL`, revealed the functions that were imported from various other link libraries of the code such as WS2_32.DLL which has networking capabalities tasks such as `bind` , `accept` , `connect` and closing `socket`. 

---
# Lab 1-4

## Executive Summary
The sample appear to be malware, and it seems it will be running a service named `MalService` on the infected machine that would enable it in connecting to a website `www.malwareanalysis.com` to download other malwares to infect an affected computer system and people on its network.

## Indicators of Compromise

**Compilation Date :** JANUARY 2011

**MD5 Hash (EXE):** 8363436878404da0ae3e46991e355b83 

**SHA-256 (EXE):** 8bcbe24929951d8aae6018b87b5ca799efe47aeb623e6e5d3665814c6d59aeae

**URLs:** http://www.malwareanalysisbook.com/

**Service Name:** MalService


## Mitigations
- Scanning through a computer system to see if is running a service called `MalService` then it implies the machine is infected

## Evidence

Opening the Lab file with PEiD, it can be seen that the file is packed with UPX a packing utililty. Using an unpacker it was able to unpack the file and get it to be recognized as Microsoft visual file that was written and compiled using Microsoft Visual C++ 6.0

Using DependencyWalker on the  unpacked`.EXE`, to find the imports of the unpacked file, `InternetOpenUrlA` and `InternetOpenA` were revealed and they serve as a proof of the capability of the file connecting to the internet and in addition `CreateService` which is an import of the dynamic link library advapi32.dll serves as a proof that this suspected malware is capable of creating services on machines it infects to spread its infections.

Opening the unpacked`.EXE` using BinText GUI, suggests that infected machines will connect to `http://www.malwareanalysis.com` and in addition a running service named `MalService` for creating services that connects to the web and downloading of malwares  to infect the computer system and other machines on the network.

---

## Tools used and their functions
- PeID : For confirming whether a file is packed or obfuscated
- BinText: A sysinternals GUI program that shows the strings in a program
- PEView: Shows useful summary information about the portable executable(s), including compile time and imports
- Dependency Walker: For showing imports

