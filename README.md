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
as `MyApplication.exe`. This can also be a `.dll` module, if present in the `Process.Modules` list. Unity games do not
work with SimpleMem due to `mono.dll` being external to the process.

## Reading and Writing Memory

📌 __For all memory examples we will use a made-up game, `MyGame`.__

Open the application, in this case `MyGame.exe`.

### Reading Memory

Create a new `Memory` object.

```cs
var mem = new Memory("MyGame"); // Your process name here

// Or, specify a module too. This module must exist within
// the process's "Modules" property (a ProcessModuleCollection object).
// See https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.processmodulecollection?view=net-6.0
var mem = new Memory("MyGame", "mydll.dll");
```

To read the value located at a pointer in memory, create a pointer to the address and call `ReadMemory()` or `ReadMemory<T>()`.

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
always a `.exe` or `.dll` - make sure this is specified upon construction of `Memory`.

To identify pointer chains, Cheat Engine's pointer scanner feature can be used. More info can be
found [here](https://cheatengine.org/help/pointer-scan.htm). For this example, our desired value will rest
at `"MyGame.exe"+0x74DF02 -> 0x04 -> 0x28` where `->` represents a pointer from one address to the next,
as seen in Cheat Engine. The value read at the end of the pointer chain (`...0x28`) contains our desired value.

__Pointer chain example__

```cs
static class Offsets
{
    // For this example, "PlayerBase" refers to some arbitrary "player" data structure base address.
    public const int PlayerBase = 0x74DF02;

    // Offsets to locate desired value - "health" which is a float (in this example).
    // PlayerBase and 0x4 are both pointers in memory. 
    // 0xC is the offset at which our health float lays from the previous pointer.
    public static readonly MultiLevelPtr<float> PlayerHealth = new MultiLevelPtr<int>(PlayerBase, 0x4, 0xC);
}

public class Main
{
    private readonly Memory _mem;

    public Main()
    {
        // Don't specify .exe here
        _mem = new Memory("MyGame");
    }

    void ReadValueFromPointerChain()
    {
        // Traditional read
        int desiredValue = _mem.ReadValueFromMlPtr<int>(Offsets.PlayerHealth);
        
        // Using extensions
        int desiredValue = Offsets.PlayerHealth.Value(_mem);
        
        // Work with the value below...
    }

    void WriteValueToPointerChain()
    {
        // Assumes address at the end of the pointer chain is int.
        // This should be known by the programmer already.
        int newValue = 500;
        
        // Traditional write
        int address = _mem.ReadAddressFromMlPtr(Offsets.PlayerHealth);
        _mem.WriteMemory(address, newValue);
        
        // Using extensions
        Offsets.PlayerHealth.WriteValue(_mem, newValue);
    }
}
```