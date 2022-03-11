# SimpleMem

<img src="logo.png"></img>

The best general-purpose memory reader/writer for C#

<img src="https://img.shields.io/nuget/v/SimpleMem"> <img src="https://img.shields.io/github/license/hburn7/SimpleMem">

## Prerequisites

- ⚠️ SimpleMem only runs on Windows.
- Install the [NuGet package](https://www.nuget.org/packages/SimpleMem/)
- Install the [.NET 6 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/6.0) (if needed)

## Getting Started

📌 **Note:** Manipulating memory in 64-bit applications requires your source to be compiled in x64.

If not known, find the name of the process you wish to hook into. The name found in this list that matches your target
application is what we will refer to as the process name.

```cs
using SimpleMem;

// Prints all process names on your system.
Memory.PrintProcessList();
```

Find the name of the base module, if not known. This is typically the name of the process name and its extension, such
as `MyApplication.exe`. This can also be a `.dll` *.dll support is untested as of v1.1.0*.

## Reading and Writing Memory

📌 __For all memory examples we will use a made-up game, `MyGame`.__

Open the application, in this case `MyGame.exe`.

### Reading Memory

Create a new `Memory` object.

```cs
var mem = new Memory("MyGame"); // Your process name here
```

To read the value located at a memory address, create a pointer to the address and call `ReadMemory...` on it
(`...` changes depending on the desired return type).

```cs
const int ADDRESS = 0xABCD123; // Your address here

// Example. Assumes "points" are located at ADDRESS and are stored as an int.
int points = mem.ReadMemory<int>(new IntPtr(ADDRESS));
```

### Writing Memory

Using the same example above, say we want to overwrite the value.

```cs
const int ADDRESS = 0xABCD123; // Your address here
const int NEW_VALUE = 500;

var mem = new Memory("MyGame"); // Your process name here
int bytesRead = mem.WriteMemory(new IntPtr(ADDRESS), NEW_VALUE); // Replaces value at ADDRESS with NEW_VALUE
```

It's that easy!

### Multi-Level Pointers

SimpleMem provides full support for reading addresses and values from base addresses and offsets.

First, find the module name - this can easily be found via [Cheat Engine](https://cheatengine.org/). This is almost
always a `.exe` or `.dll` and is known as the `ModuleBaseAddress`. By default, it is your application's executable.

To identify pointer chains, Cheat Engine's pointer scanner feature can be used. More info can be
found [here](https://cheatengine.org/help/pointer-scan.htm). For this example, our desired value will rest
at `MyGame.exe+0x74DF02 -> 0x04 -> 0x28` where `->` represents a pointer from one address to the next. The value read at
the end of the pointer chain (`...0x28`) contains our desired value.

__Pointer chain example__

```cs
static class Offsets
{
    // For this example, "PlayerBase" refers to some arbitrary player in a video game.
    public const int PlayerBase = 0x74DF02;

    // Offsets to locate desired value
    public static int[] PlayerHealthOffsets = new int[] { PlayerBase, 0x04, 0x28 };
}

public class Main
{
    private readonly Memory _mem;

    public Main()
    {
        // If your module is different than "MyGame.exe", specify
        _mem = new MemoryModule("MyGame");
    }

    // Reads value from the address resulting from the pointer chain
    void ReadValueFromPointerChain()
    {
        var mlPtr = new MultiLevelPtr(_mem.ModuleBaseAddress, PlayerHealthOffsets);
        int desiredValue = _mem.GetValFromMlPtr<int>(mlPtr);
        // etc...
    }

    // Writes value to the address resulting from the pointer chain
    void WriteValueToPointerChain()
    {
        // Assumes address at the end of the pointer chain is int.
        // This should be known by the programmer already.
        int newValue = 500;
        
        var mlPtr = new MultiLevelPtr(_mem.ModuleBaseAddress, PlayerHealthOffsets);
        int address = _mem.GetAddressFromMlPtr(mlPtr);
        
        _mem.WriteMemory(address, newValue);
    }
}
```

## Remarks

- The library does not handle any errors arising from:
    - Inability to find the process
    - Inability to read memory from the given address or offsets
    - Bad memory writes (writing to wrong address, writing bad values, etc.)
- Strings are not currently supported