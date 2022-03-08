using System.Diagnostics;

namespace SimpleMem;

/// <summary>
///  Class for reading and writing memory in 32-bit processes with support for
///  reading values and addresses from multi-level pointers (referred to here as a pointer chain).
/// </summary>
public class MemoryChain32 : Memory32
{
	/// <summary>
	/// </summary>
	/// <param name="processName">
	///  The name of the process. Use <see cref="Memory.GetProcessList" />
	///  and find your process name if unsure. That value can be passed in as this parameter.
	/// </param>
	/// <param name="moduleName">The name of the module (with extension .exe, .dll, etc.)</param>
	/// <param name="accessLevel">The desired access level.
	/// The minimum required for reading is AccessLevel.READ and the minimum required
	/// for writing is AccessLevel.WRITE | AccessLevel.OPERATION.
	/// AccessLevel.ALL_ACCESS gives full read-write access to the process.</param>
	public MemoryChain32(string processName, string moduleName, AccessLevel accessLevel = AccessLevel.ALL_ACCESS) : base(processName,
		accessLevel)
	{
		ModuleName = moduleName;
		ModuleBaseAddress = GetModuleBaseAddress(GetProcess());
	}

	/// <summary>
	///  Name of the module that serves as the base address.
	/// </summary>
	public string ModuleName { get; }
	/// <summary>
	///  Pointer to the memory address of the module, also known as the "module base address".
	/// </summary>
	public IntPtr ModuleBaseAddress { get; }

	private IntPtr GetModuleBaseAddress(Process proc)
	{
		var module = proc.Modules
		                 .Cast<ProcessModule>()
		                 .SingleOrDefault(m => string.Equals(m.ModuleName, ModuleName,
			                 StringComparison.OrdinalIgnoreCase));

		// Attempt to get the base address of the module - Return IntPtr.Zero if the module doesn't exist in the process
		return module?.BaseAddress ?? IntPtr.Zero;
	}

	/// <summary>
	///  Finds the address from a chain of pointers repeatedly applied to lpBaseAddress.
	///  <param name="offsets">An array of hexadecimal offsets to apply to lpBaseAddress.</param>
	///  <param name="lpBaseAddress">
	///   Optional base address. By default it is the ModuleBaseAddress
	///   (the address of "MyApplication.exe", for example).
	///  </param>
	///  <returns>
	///   The memory address that results from the end of the pointer chain.
	///   Call a matching ReadMemory method on this address to retrieve the value located
	///   at this address.
	///  </returns>
	///  <example>
	///   Say your desired value is located at "MyApplication.exe"+0xABCD with
	///   pointers 0xA, 0xB, and 0xC. Pass in the 4 hexadecimals as offsets and leave
	///   lpBaseAddress null if your "MyApplication.exe" is the same as the module name.
	///   <code>
	/// var mem = new Memory32("MyApplication", "MyApplication.exe");
	/// // Assuming the resulting value at this offset is an Int32.
	/// Int32[] myItemOffsets = { 0xABCD, 0xA, 0xB, 0xC };
	/// Int32 myItemAddress = mem.GetAddressFromPointerChain(myItemOffsets);
	/// var value = mem.ReadInt32(myItemAddress);
	/// </code>
	///  </example>
	/// </summary>
	public Int32 GetAddressFromPointerChain(Int32[] offsets, Int32? lpBaseAddress = null)
	{
		lpBaseAddress ??= ModuleBaseAddress.ToInt32();

		if (offsets.Length == 0)
		{
			return lpBaseAddress.Value;
		}

		// Read whatever value is located at the baseAddress. This is our new address.
		Int32 res = ReadMemoryInt32(lpBaseAddress.Value + offsets[0]);
		foreach (Int32 offset in offsets[1..])
		{
			Int32 nextAddress = res + offset;
			if (offset == offsets[^1])
			{
				// Return address of item we're interested in.
				// Returning a ReadMemory here would result in the value of the item.
				return nextAddress;
			}

			// Keep looking for address
			res = ReadMemoryInt32(res + offset);
		}

		return res;
	}

	/// <summary>
	///  Calls GetAddressFromPointerChain and returns the value of the object at the end of the pointer chain.
	///  Useful to save one additional memory read call on the address returned from that address.
	/// </summary>
	/// <param name="offsets">An array of hexadecimal offsets to apply to lpBaseAddress.</param>
	/// <param name="lpBaseAddress">
	///  Optional base address. By default it is the ModuleBaseAddress
	///  (the address of "MyApplication.exe", for example).
	/// </param>
	/// <returns>Value stored at the end of the pointer chain</returns>
	public short GetShortFromPointerChain(Int32[] offsets, Int32? lpBaseAddress = null) =>
		ReadMemoryShort(GetAddressFromPointerChain(offsets, lpBaseAddress));

	/// <summary>
	///  Calls GetAddressFromPointerChain and returns the value of the object at the end of the pointer chain.
	///  Useful to save one additional memory read call on the address returned from that address.
	/// </summary>
	/// <param name="offsets">An array of hexadecimal offsets to apply to lpBaseAddress.</param>
	/// <param name="lpBaseAddress">
	///  Optional base address. By default it is the ModuleBaseAddress
	///  (the address of "MyApplication.exe", for example).
	/// </param>
	/// <returns>Value stored at the end of the pointer chain</returns>
	public Int32 GetInt32FromPointerChain(Int32[] offsets, Int32? lpBaseAddress = null) =>
		ReadMemoryInt32(GetAddressFromPointerChain(offsets, lpBaseAddress));

	/// <summary>
	///  Calls GetAddressFromPointerChain and returns the value of the object at the end of the pointer chain.
	///  Useful to save one additional memory read call on the address returned from that address.
	/// </summary>
	/// <param name="offsets">An array of hexadecimal offsets to apply to lpBaseAddress.</param>
	/// <param name="lpBaseAddress">
	///  Optional base address. By default it is the ModuleBaseAddress
	///  (the address of "MyApplication.exe", for example).
	/// </param>
	/// <returns>Value stored at the end of the pointer chain</returns>
	public Int64 GetInt64FromPointerChain(Int32[] offsets, Int32? lpBaseAddress = null) =>
		ReadMemoryInt64(GetAddressFromPointerChain(offsets, lpBaseAddress));

	/// <summary>
	///  Calls GetAddressFromPointerChain and returns the value of the object at the end of the pointer chain.
	///  Useful to save one additional memory read call on the address returned from that address.
	/// </summary>
	/// <param name="offsets">An array of hexadecimal offsets to apply to lpBaseAddress.</param>
	/// <param name="lpBaseAddress">
	///  Optional base address. By default it is the ModuleBaseAddress
	///  (the address of "MyApplication.exe", for example).
	/// </param>
	/// <returns>Value stored at the end of the pointer chain</returns>
	public ushort GetUShortFromPointerChain(Int32[] offsets, Int32? lpBaseAddress = null) =>
		ReadMemoryUShort(GetAddressFromPointerChain(offsets, lpBaseAddress));

	/// <summary>
	///  Calls GetAddressFromPointerChain and returns the value of the object at the end of the pointer chain.
	///  Useful to save one additional memory read call on the address returned from that address.
	/// </summary>
	/// <param name="offsets">An array of hexadecimal offsets to apply to lpBaseAddress.</param>
	/// <param name="lpBaseAddress">
	///  Optional base address. By default it is the ModuleBaseAddress
	///  (the address of "MyApplication.exe", for example).
	/// </param>
	/// <returns>Value stored at the end of the pointer chain</returns>
	public UInt32 GetUInt32FromPointerChain(Int32[] offsets, Int32? lpBaseAddress = null) =>
		ReadMemoryUInt32(GetAddressFromPointerChain(offsets, lpBaseAddress));

	/// <summary>
	///  Calls GetAddressFromPointerChain and returns the value of the object at the end of the pointer chain.
	///  Useful to save one additional memory read call on the address returned from that address.
	/// </summary>
	/// <param name="offsets">An array of hexadecimal offsets to apply to lpBaseAddress.</param>
	/// <param name="lpBaseAddress">
	///  Optional base address. By default it is the ModuleBaseAddress
	///  (the address of "MyApplication.exe", for example).
	/// </param>
	/// <returns>Value stored at the end of the pointer chain</returns>
	public UInt64 GetUInt64FromPointerChain(Int32[] offsets, Int32? lpBaseAddress = null) =>
		ReadMemoryUInt64(GetAddressFromPointerChain(offsets, lpBaseAddress));

	/// <summary>
	///  Calls GetAddressFromPointerChain and returns the value of the object at the end of the pointer chain.
	///  Useful to save one additional memory read call on the address returned from that address.
	/// </summary>
	/// <param name="offsets">An array of hexadecimal offsets to apply to lpBaseAddress.</param>
	/// <param name="lpBaseAddress">
	///  Optional base address. By default it is the ModuleBaseAddress
	///  (the address of "MyApplication.exe", for example).
	/// </param>
	/// <returns>Value stored at the end of the pointer chain</returns>
	public float GetFloatFromPointerChain(Int32[] offsets, Int32? lpBaseAddress = null) =>
		ReadMemoryFloat(GetAddressFromPointerChain(offsets, lpBaseAddress));

	/// <summary>
	///  Calls GetAddressFromPointerChain and returns the value of the object at the end of the pointer chain.
	///  Useful to save one additional memory read call on the address returned from that address.
	/// </summary>
	/// <param name="offsets">An array of hexadecimal offsets to apply to lpBaseAddress.</param>
	/// <param name="lpBaseAddress">
	///  Optional base address. By default it is the ModuleBaseAddress
	///  (the address of "MyApplication.exe", for example).
	/// </param>
	/// <returns>Value stored at the end of the pointer chain</returns>
	public double GetDoubleFromPointerChain(Int32[] offsets, Int32? lpBaseAddress = null) =>
		ReadMemoryDouble(GetAddressFromPointerChain(offsets, lpBaseAddress));

	/// <summary>
	///  Calls GetAddressFromPointerChain and returns the value of the object at the end of the pointer chain.
	///  Useful to save one additional memory read call on the address returned from that address.
	/// </summary>
	/// <param name="offsets">An array of hexadecimal offsets to apply to lpBaseAddress.</param>
	/// <param name="lpBaseAddress">
	///  Optional base address. By default it is the ModuleBaseAddress
	///  (the address of "MyApplication.exe", for example).
	/// </param>
	/// <returns>Value stored at the end of the pointer chain</returns>
	public string GetStringFromPointerChain(Int32[] offsets, Int32? lpBaseAddress = null) =>
		ReadMemoryString(GetAddressFromPointerChain(offsets, lpBaseAddress));

	/// <summary>
	///  Calls GetAddressFromPointerChain and returns the value of the object at the end of the pointer chain.
	///  Useful to save one additional memory read call on the address returned from that address.
	/// </summary>
	/// <param name="offsets">An array of hexadecimal offsets to apply to lpBaseAddress.</param>
	/// <param name="lpBaseAddress">
	///  Optional base address. By default it is the ModuleBaseAddress
	///  (the address of "MyApplication.exe", for example).
	/// </param>
	/// <returns>Value stored at the end of the pointer chain</returns>
	public bool GetBoolFromPointerChain(Int32[] offsets, Int32? lpBaseAddress = null) =>
		ReadMemoryBool(GetAddressFromPointerChain(offsets, lpBaseAddress));

	/// <summary>
	///  Calls GetAddressFromPointerChain and returns the value of the object at the end of the pointer chain.
	///  Useful to save one additional memory read call on the address returned from that address.
	/// </summary>
	/// <param name="offsets">An array of hexadecimal offsets to apply to lpBaseAddress.</param>
	/// <param name="lpBaseAddress">
	///  Optional base address. By default it is the ModuleBaseAddress
	///  (the address of "MyApplication.exe", for example).
	/// </param>
	/// <returns>Value stored at the end of the pointer chain</returns>
	public byte GetByteFromPointerChain(Int32[] offsets, Int32? lpBaseAddress = null) =>
		ReadMemoryByte(GetAddressFromPointerChain(offsets, lpBaseAddress));

	/// <summary>
	///  Calls GetAddressFromPointerChain and returns the value of the object at the end of the pointer chain.
	///  Useful to save one additional memory read call on the address returned from that address.
	/// </summary>
	/// <param name="offsets">An array of hexadecimal offsets to apply to lpBaseAddress.</param>
	/// <param name="lpBaseAddress">
	///  Optional base address. By default it is the ModuleBaseAddress
	///  (the address of "MyApplication.exe", for example).
	/// </param>
	/// <returns>Value stored at the end of the pointer chain</returns>
	public char GetCharFromPointerChain(Int32[] offsets, Int32? lpBaseAddress = null) =>
		ReadMemoryChar(GetAddressFromPointerChain(offsets, lpBaseAddress));
}