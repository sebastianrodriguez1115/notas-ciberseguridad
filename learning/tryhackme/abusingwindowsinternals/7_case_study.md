# Task 7 - Case Study in Browser Injection and Hooking

To get hands on with the implications of process injection we can observe the TTPs (Tactics, Techniques, and Procedures) of TrickBot.

Credit for initial research: [SentinelLabs](https://www.sentinelone.com/labs/how-trickbot-malware-hooking-engine-targets-windows-10-browsers/) The main function of the malware we will be observing is browser hooking. Browser hooking allows the malware to hook interesting API calls that can be used to intercept/steal credentials.

## Targeting Browsers

From SentinelLabs' reverse engineering, TrickBot uses `OpenProcess` to obtain handles for common browser paths. In the disassembly, we can see it searching for:
- `chrome.exe`
- `iexplore.exe`
- `firefox.exe`
- `microsoftedgecp.exe`

## Reflective Injection Flow

TrickBot uses a form of reflective injection with the following 7 steps:

1. **Open Target Process**: `OpenProcess`
2. **Allocate memory**: `VirtualAllocEx`
3. **Copy function into allocated memory**: `WriteProcessMemory`
4. **Copy shellcode into allocated memory**: `WriteProcessMemory`
5. **Flush cache to commit changes**: `FlushInstructionCache`
6. **Create a remote thread**: `RemoteThread` (likely `CreateRemoteThread`)
7. **Resume the thread or fallback**: `ResumeThread` or `RtlCreateUserThread`

## Hooking Functionality

Once injected, TrickBot calls its **hook installer function**. The installer function performs the following operations:

1. **Calculate Offsets**: Determines the relative offset for the jump.
2. **Modify Permissions**: Uses `VirtualProtectEx` to change memory protection to `0x40` (`PAGE_EXECUTE_READWRITE`).
3. **Write Hook**: Overwrites the beginning of the original function with a `JMP` instruction (`0xE9` opcode) pointing to the malicious code.
4. **Restore Permissions**: Returns the memory to its original protection state.

The main takeaway is that TrickBot injects itself into browser processes using reflective injection and then hooks API calls from the injected function to intercept sensitive data.
