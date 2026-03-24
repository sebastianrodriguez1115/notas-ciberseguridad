# Injecting Payloads Into Windows Portable Executables

Using Msfvenom you can inject installers .exe with payloads, for example WinRAR:

![](Injecting Payloads Into Windows Portable Executabl/Untitled.png)

Using the -k option will maintain the original .exe functionality, but it rarely works:

![](Injecting Payloads Into Windows Portable Executabl/Untitled 1.png)

Also antivirus will detect this very easily.
