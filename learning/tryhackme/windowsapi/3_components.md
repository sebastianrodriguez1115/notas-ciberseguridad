# Task 3 - Components of the Windows API

The Win32 API, more commonly known as the Windows API, has several dependent components that are used to define the structure and organization of the API.

Let's break the Win32 API up via a top-down approach. We'll assume the API is the top layer and the parameters that make up a specific call are the bottom layer. In the table below, we will describe the top-down structure at a high level and dive into more detail later.

| Layer | Explanation |
|---|---|
| API | A top-level/general term or theory used to describe any call found in the win32 API structure. |
| Header files or imports | Defines libraries to be imported at run-time, defined by header files or library  imports. Uses pointers to obtain the function address. |
| Core DLLs | A group of four DLLs that define call structures. (KERNEL32, USER32, and ADVAPI32). These DLLs  define kernel and user services that are not contained in a single subsystem. |
| Supplemental DLLs | Other DLLs defined as part of the Windows API. Controls separate subsystems of the Windows  OS. ~36 other defined DLLs. (NTDLL, COM, FVEAPI, etc.) |
| Call Structures | Defines the API call itself and parameters of the call. |
| API Calls | The API call used within a program, with function addresses obtained from pointers. |
| In/Out Parameters | The parameter values that are defined by the call structures. |

Let's expand these definitions; in the next task, we will discuss importing libraries, the core header file, and the call structure. In task 4, we will dive deeper into the calls, understanding where and how to digest call parameters and variants.

