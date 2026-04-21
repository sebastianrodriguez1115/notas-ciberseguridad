# Task 4 - OS Libraries

Each call of the Win32 library resides in memory and requires a pointer to a memory address. The process of obtaining pointers to these functions is obscured because of **ASLR** (Address Space Layout Randomization) implementations; each language or package has a unique procedure to overcome ASLR. Throughout this room, we will discuss the two most popular implementations: P/Invoke and the Windows header file.

In this task, we will take a deep dive into the theory of how both of these implementations work, and in futuretasks, we will put them to practical use.

## Windows Header File

Microsoft has released the Windows header file, also known as the Windows loader, as a direct solution to the
problems associated with ASLR's implementation. Keeping the concept at a high level, at runtime, the loader will determine what calls are being made and create a thunk table to obtain function addresses or pointers.

Luckily, we do not have to dive deeper than that to continue working with calls if we do not desire to do so.

Once the `windows.h` file is included at the top of an unmanaged program; any Win32 function can be called.

We will cover this concept at a more practical level in task 6.

## P/Invoke

Microsoft describes P/Invoke or platform invoke as *"a technology that allows you to access structs, callbacks,and functions in unmanaged libraries from your managed code."*

P/Invoke provides tools to handle the entire process of invoking an unmanaged function from managed code or, inother words, calling the Win32 API. P/Invoke will kick off by importing the desired DLL that contains the unmanaged function or Win32 API call. Below is an example of importing a DLL with options.

```csharp
using System;
using System.Runtime.InteropServices;

public class Program
{
  [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  ...
}
```

In the above code, we are importing the `user32` using the attribute: `DLLImport`.

> **Note:** a semicolon is not included because the P/Invoke function is not yet complete. In the second step, we must define a managed method as an external one. The `extern` keyword will inform the runtime of the specific DLL that was previously imported. Below is an example of creating the external method.

```csharp
using System;
using System.Runtime.InteropServices;

public class Program
{
  ...
  private static extern int MessageBox(IntPtr hWnd, string lpText, string lpCaption, uint uType);
}
```

Now we can invoke the function as a managed method, but we are calling the unmanaged function!

We will cover this concept at a more practical level in task 7.
