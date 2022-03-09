using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;

namespace SimpleMem;

/// <summary>
///  Class for reading and writing memory in 32-bit processes with support for
///  reading values and addresses from multi-level pointers (referred to here as a pointer chain).
/// </summary>
public class MemoryChain32 : Memory32
{
	private readonly string _moduleName;
	
	/// <summary>
	/// </summary>
	/// <param name="processName">
	///  The name of the process. Use <see cref="Memory.GetProcessList" />
	///  and find your process name if unsure. That value can be passed in as this parameter.
	/// </param>
	/// <param name="moduleName">The name of the module (with extension .exe, .dll, etc.) By
	/// default, this evaluates to the process's main module name, which is almost always the
	/// name of the executable.</param>
	/// <param name="accessLevel">The desired access level.
	/// The minimum required for reading is AccessLevel.READ and the minimum required
	/// for writing is AccessLevel.WRITE | AccessLevel.OPERATION.
	/// AccessLevel.ALL_ACCESS gives full read-write access to the process.</param>
	public MemoryChain32(string processName, string? moduleName = null, 
		AccessLevel accessLevel = AccessLevel.ALL_ACCESS) : base(processName, accessLevel)
	{
		_moduleName = moduleName ?? Process.MainModule?.ModuleName ?? "<module not found>";

		if (moduleName == null)
		{
			Module = Process.MainModule ?? throw new InvalidOperationException("Process has no main module.");
		}
		else
		{
			Module = GetModule(Process);
		}
	}
	
	/// <summary>
	/// Module assosciated with the provided moduleName, or the process's MainModule by default.
	/// </summary>
	public ProcessModule Module { get; }

	private ProcessModule GetModule(Process proc)
	{
		var module = proc.Modules
		                 .Cast<ProcessModule>()
		                 .SingleOrDefault(module => string.Equals(module.ModuleName, _moduleName, StringComparison.OrdinalIgnoreCase));

		if (module == null)
		{
			throw new InvalidOperationException($"Could not retrieve the module {_moduleName}.");
		}
		
		return module;
	}
	
	public List<IntPtr> AoBScan(string pattern)
	{
		int bytesRead = 0;
		
		// Get min & max addresses

		SYSTEM_INFO sysInfo = new SYSTEM_INFO();
		GetSystemInfo(out sysInfo);

		IntPtr procMinAddress = sysInfo.minimumApplicationAddress;
		IntPtr procMaxAddress = sysInfo.maximumApplicationAddress;

		Int64 procMinAddressL = (long)procMinAddress;
		Int64 procMaxAddressL = (long)procMaxAddress;

		MEMORY_BASIC_INFORMATION memBasicInfo = new MEMORY_BASIC_INFORMATION();
		
		Int32[] intBytes = transformBytes(pattern);
		
		var ret = new List<IntPtr>();
		while (procMinAddressL < procMaxAddressL)
		{
			// Console.WriteLine($"Scanning...{procMinAddressL:X} - {procMaxAddressL:X}");
			// 28 = sizeof(MEMORY_BASIC_INFORMATION)
			VirtualQueryEx(ProcessHandle, procMinAddress, out memBasicInfo, 48);
			
			// Check to see if chunk is accessible
			if (memBasicInfo.Protect == PAGE_READWRITE && memBasicInfo.State == MEM_COMMIT)
			{
				byte[] buffer = new byte[memBasicInfo.RegionSize];
				ReadProcessMemory((Int32)ProcessHandle, (int)memBasicInfo.BaseAddress, buffer, (int)memBasicInfo.RegionSize, ref bytesRead);
				
				var results = new List<IntPtr>();

				for (int i = 0; i < buffer.Length; i++)
				{
					for (int j = 0; j < intBytes.Length; j++)
					{
						if (intBytes[j] != -1 && intBytes[j] != buffer[i + j])
						{
							if(j > 2)
								Console.WriteLine($"Broken chain (len={j})");
							break;
						}
						
						if ((j + 1) == intBytes.Length)
						{
							var result = new IntPtr(i + Module.BaseAddress.ToInt32());
							results.Add(result);
						}
					}
				}
				
				ret.AddRange(results);
			}
			
			procMinAddressL += (long) memBasicInfo.RegionSize;
			procMinAddress = new IntPtr(procMinAddressL);
		}

		return ret;
		
		// Helper method
		Int32[] transformBytes(string signature)
		{
			string[] bytes = signature.Split(' ');
			Int32[] ints = new int[bytes.Length];

			var regexes = new Regex[]
			{
				new Regex(@"\?[0-9]"),
				new Regex(@"[0-9]\?")
			};
			
			for (int i = 0; i < ints.Length; i++)
			{
				if (bytes[i] == "??" || regexes.Any(x => x.IsMatch(bytes[i])))
				{
					ints[i] = -1;
				}
				else
				{
					ints[i] = Int32.Parse(bytes[i], NumberStyles.HexNumber);
				}
			}

			return ints;
		}
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
		lpBaseAddress ??= Module.BaseAddress.ToInt32();

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