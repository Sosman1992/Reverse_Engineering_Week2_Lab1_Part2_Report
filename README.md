# Week 1 - Simple Static Analysis

This Week's Lab focus was on the use of file hashes as a technique to recognize whether an executable file is a malware. This was achieved by submitting or uploading the executable file or hashes via Google's VirusTotal website to scan the files with a variety of antivirus programs embedded in the website. Furthermore used BinText GUI  to search for ASCII and Unicode `strings` inside the binary of the executable file and also discovered how to use PEiD to determine whether the binary of a malware sample(s) executable or linked library file is compressed to conceal its contents as a countermeasure; so that it can not analyzed for mitigation measures to be implemented against it by a malware analyst. Lastly exploration of Windows system tools that are used by portable executable including libraries that get dynamically linked when an executable file is effected on a computer or network system and which functions are imported was also learnt.

---
# Lab 1-3 

## Executive Summary

The executable is a malware recognized by virusTotal because it was detected by different antivirus program(s) on this website as a malicious software. The file appears to be a packed malware and trying to unpack it with UPX utility tool was not successful. Using the PeID utility tool to open the sample and analyzing the sample goes on further to prove that FSG (a different variant packer - a utility tool used to compress a file to hide its content) was used in compression of this file. Also opening the file in PEview shows that it is lacking import table and without the import table I am unable to know the functions and linking libraries used by this executable sample when it infects machines or users on a network, Nonetheless, opening the file with Dependency Walker it shows the import table of this executable with two functions namely `LoadLibrary` and `GetProcAddress` that are always associated with any Packed files. This further indicate that this file is packed. In conclusion running the sample using the known tools I know for performing static analysis did not provide any useful information for a host-based indicator or network signature, that can serve as the indicators of compromise, and also provide mitigation(s) measures required for protection from the infection of this malware to a computer or network systems of victims that gets infected with it.

## Indicators of Compromise 

## Mitigations
- Using further analysis techniques, is what can help to provide the solution against this kind of malware.

## Evidence

The malware is a portable executable (EXE) and uploading it to VirusTotal antivirus engines triggers the sample to be a malware by different antivirus database on the website.

Opening the file with PEiD indicates that the file was packed with FSG packer

Using Dependency Walker on the `.EXE`, further revealed that the file is packed because the were two functions present in its import address table that are always associated with any Portable Executable file that is packed. 

---
# Lab 1-4

## Executive Summary
The file is a portable executable, more specifically a `WIN32.EXE` file. There is no indication that the file is either packed or obfuscated using PEiD utility software tool and also PEiD provided me with more information that the file was written and compiled using Microsoft Visual C++ 6.0. In addition, using PEview the file header indicates that this application was created in August of 2019. Using Dependency Walker to open the file I saw that the file was composed of three dynamic link library it uses in it operation namely `kernel32`, `ADVAPI32` and `MSCRVT`. The imports from kernel32.dll shows that file loads data from the resource section by importing the functions `LoadResource` , `FindResource` , `SizeOfResource`, writes a file to disk using the function `CreateFile`, `WriteFile`, and executes a file on disk of infected machines using `WinExec` function. Also the imports from ADVAPI32 indicates that the file posses priviliged related information due to the priviliged functions associated with the imports. In addition this file will updates itself with other malware `updater.exe` on infected machines or network because running strings command on this PE file, revealed that it connects to the website `www.malwareanalysisbook.com/updater.exe` a  network-based indicator to obtain other/additional files through the URL which may be malwares from the. Lastly using PEview it can be seen that this PE file has one resource at SECTION.rsrc namely`BIN 0065 0409` and this file can be demonstrated using Resource HAcker tool to save its sbinary into executable format;then using PEiD utility tool it confirms that this resource file is neither packed nor obfuscated and running `string` function through it can been seen that. Also uploading the saved binary both on virusTotal and PEview shows the the compilation date for this hidden file is 2011, and the data section for this saved file where the DLL are present have similar functions to the lab01-4 executable file

## Indicators of Compromise

**Compilation Date (ASSUMED):** AUGUST 2019

**MD5 Hash (EXE):**	625ac05fd47adc3c63700c3b30de79ab

**SHA-1 (EXE):**	9369d80106dd245938996e245340a3c6f17587fe

**SHA-256 (EXE):**	0fa1498340fca6c562cfa389ad3e93395f44c72fd128d7ba08579a69aaf3b126

**File to look for:** `C:\windows\system32\wupdmgr.exe`

**File Type:** `.EXE`

## Mitigations
- Deletions of files matching any of these hashes obtained from the scanning result from the VirusTotal website
- Scan Windows machines for `system32\wupdmgr.exe`

## Evidence

Opening the Lab file with PEiD, it can be seen that the file is neither packed nor obfuscated and also provided us with more information that, the file  was written and compiled using Microsoft Visual C++ 6.0

Using DependencyWalker on the  unpacked`.EXE`, to find the imports of the unpacked file, `InternetOpenUrlA` and `InternetOpenA` were revealed and they serve as a proof of the capability of the file connecting to the internet and in addition `CreateService` which is an import of the dynamic link library advapi32.dll serves as a proof that this suspected malware is capable of creating services on machines it infects to spread its infections.

Opening the unpacked`.EXE` using BinText GUI, suggests that infected machines will connect to `http://www.malwareanalysis.com` and in addition a running service named `MalService` for creating services that connects to the web and downloading of malwares  to infect the computer system and other machines on the network.

---

## Tools used and their functions
- PeID : For confirming whether a file is packed or obfuscated
- BinText: A sysinternals GUI program that shows the strings in a program
- PEView: Shows useful summary information about the portable executable(s), including compile time and imports
- Dependency Walker: For showing imports
- strings: A sysinternals command line program for showing the characters in an executable.
