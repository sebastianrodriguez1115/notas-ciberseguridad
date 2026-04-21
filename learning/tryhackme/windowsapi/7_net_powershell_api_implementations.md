# Task 7 - .NET and PowerShell API Implementations

As discussed in task 4, P/Invoke allows us to import DLLs and assign pointers to calls.

To understand how P/Invoke is implemented, let's jump right into it with an example below and discuss individual components afterward.

```csharp
class Win32 {
  [DllImport("kernel32")]
  public static extern IntPtr GetComputerNameA(StringBuilder lpBuffer, ref uint lpnSize);
}
```

The class function stores defined API calls and a definition to reference in all future methods.

The library in which the API call structure is stored must now be imported using `DllImport`. The imported DLLsact similar to the header packages but require that you import a specific DLL with the call you are looking for.
You can reference the index or pinvoke.net to determine where a particular call is located in a DLL.

From the DLL import, we can create a new pointer to the call we want to use, notably defined by `IntPtr`. Unlike other low-level languages, you must specify the in/out parameter structure in the pointer. As discussed in task 5, we can find the in/out parameters for the required API call from the Windows documentation.

Now we can implement the defined API call into an application and use its functionality. Below is an example application that uses the API to get the computer name and other information of the device it is run on.

```csharp
class Win32 {
  [DllImport("kernel32")]
  public static extern IntPtr GetComputerNameA(StringBuilder lpBuffer, ref uint lpnSize);
}

static void Main(string[] args) {
  bool success;
  StringBuilder name = new StringBuilder(260);
  uint size = 260;
  success = GetComputerNameA(name, ref size);
  Console.WriteLine(name.ToString());
}
```

If successful, the program should return the computer name of the current device.

Now that we've covered how it can be accomplished in .NET, let's look at how we can adapt the same syntax to work in PowerShell.

Defining the call is almost identical to .NET's implementation, but we will need to create a method instead of a class and add a few additional operators.

```powershell
$MethodDefinition = @"
  [DllImport("kernel32")]
  public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
  [DllImport("kernel32")]
  public static extern IntPtr GetModuleHandle(string lpModuleName);
  [DllImport("kernel32")]
  public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint
lpflOldProtect);
"@;
```

The calls are now defined, but PowerShell requires one further step before they can be initialized. We must create a new type for the pointer of each Win32 DLL within the method definition. The function `Add-Type` will drop a temporary file in the `/temp` directory and compile needed functions using `csc.exe`. Below is an example of the function being used.

```powershell
$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -NameSpace 'Win32' -PassThru;
```

We can now use the required API calls with the syntax below.

```powershell
[Win32.Kernel32]::<Imported Call>()
```

