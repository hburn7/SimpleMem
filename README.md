# SimpleMem
<img src="logo.png"></img>

The best general-purpose memory reader/writer for C# 

<img src="https://img.shields.io/nuget/v/SimpleMem"> <img src="https://img.shields.io/github/license/hburn7/SimpleMem">

## Prerequisites

- ⚠️ SimpleMem only runs on Windows.
- ⚠️ Support for manipulating memory in 64-bit processes will be coming in a later update.
- Install the [NuGet package](https://www.nuget.org/packages/SimpleMem/)
- Install the [.NET 6 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/6.0) (if needed)

## Getting Started

If not known, find the name of the process you wish to hook into. The name found in this list that matches your target
application is what we will refer to as the process name.

```cs
using SimpleMem;

// Prints all process names on your system.
List<string> names = Memory.GetProcessList();
foreach(var n in names)
{
    Console.WriteLine(n);
}
```

Find the name of the base module, if not known. This is typically the name of the process name and its extension, such as `MyApplication.exe`. This can also be a `.dll`.



## Reading and Writing Memory

📌 __For all memory examples we will be using a made-up game, `MyGame`.__

Open the application, in this case `MyGame.exe`.

### Reading Memory

Create a new `Memory32` or `Memory64` (coming soon) object, depending on the architecture of the application. Say the address in question is `0x1234` and is an `Int32`. To read this value, we simply call `.ReadMemoryInt32()` on it.

```cs
const Int32 ADDRESS = 0x1234; // Address to read from

var mem = new Memory32("MyGame"); // Your process name here
int readValue = mem.ReadMemoryInt32(ADDRESS);
```

The same process can be applied for any type supported in `Memory32`'s other methods.

### Writing Memory

Using the same example above, say we want to overwrite the value.

```cs
const Int32 ADDRESS = 0x1234; // Address to write to
const int NEW_VALUE = 500;

var mem = new Memory32("MyGame"); // Your process name here
int bytesRead = mem.WriteMemory(ADDRESS, NEW_VALUE); // Replaces value at ADDRESS with NEW_VALUE
```

It's that easy!

### Pointer Chains
Known more popularly as multi-level pointers, SimpleMem provides full support for reading addresses and values from base addresses and offsets - it couldn't be easier!

First, find the module name - this can easily be found via [Cheat Engine](https://cheatengine.org/). This is almost always a `.exe` or `.dll` and is known as the `ModuleBaseAddress`.

To identify pointer chains, Cheat Engine's pointer scanner feature can be used. More info can be found [here](https://cheatengine.org/help/pointer-scan.htm). For this example, our desired value will rest at `MyGame.exe+0x74DF02 -> 0x04 -> 0x28` where `->` represents a pointer from one address to the next. The value read at the end of the pointer chain (`...0x28`) contains our desired value.

__Pointer chain example (32-bit).__ *Process is identical for 64-bit (coming soon)*
```cs
static class Offsets
{
    public const Int32 Base = 0x74DF02;

    // Offsets to locate desired value
    public static Int32[] DesiredValueOffsets = new Int32[] { Base, 0x04, 0x28 };
}

public class Main
{
    private readonly Memory32Chain _mem;

    public Main()
    {
        _mem = new Memory32Chain("MyGame", "MyGame.exe");
    }

    // Reads value from the address resulting from the pointer chain
    void ReadValueFromPointerChain()
    {
        int desiredValue = _mem.GetInt32FromPointerChain(Offsets.DesiredValueOffsets);
        // etc...
    }

    // Writes value to the address resulting from the pointer chain
    void WriteValueToPointerChain()
    {
        // Assumes address at the end of the pointer chain is Int32.
        // This should be known by the programmer already.
        int newValue = 500;
        Int32 address = _mem.GetAddressFromPointerChain();
        
        _mem.WriteMemory(address, newValue);
    }
}
```

## Remarks
- The library does not handle any errors arising from:
    - Inability to find the process
    - Inability to read memory from the given address or offsets
    - Bad memory writes (writing to wrong address, writing bad values, etc.)