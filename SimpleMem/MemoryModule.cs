using System.Buffers;
using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;

namespace SimpleMem;

/// <summary>
///  Class for cross-architecture memory manipulation with support for manipulation of specific modules
///  (i.e. MyApplication.exe or MyDll.dll). Support for AoBScans and resolving multi-level pointers
///  exists in this class.
/// </summary>
public class MemoryModule : Memory
{
	private readonly string _moduleName;

	/// <summary>
	/// </summary>
	/// <param name="processName">
	///  The name of the process. Use <see cref="Memory.GetProcessList" />
	///  and find your process name if unsure. That value can be passed in as this parameter.
	/// </param>
	/// <param name="moduleName">
	///  The name of the module (with extension .exe, .dll, etc.) By
	///  default, this evaluates to the process's main module name, which is almost always the
	///  name of the executable.
	/// </param>
	/// <param name="accessLevel">
	///  The desired access level.
	///  The minimum required for reading is AccessLevel.READ and the minimum required
	///  for writing is AccessLevel.WRITE | AccessLevel.OPERATION.
	///  AccessLevel.ALL_ACCESS gives full read-write access to the process.
	/// </param>
	public MemoryModule(string processName, string? moduleName = null,
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

		ModuleBaseAddress = Module.BaseAddress;
	}

	/// <summary>
	///  Module assosciated with the provided moduleName, or the process's MainModule by default.
	/// </summary>
	public ProcessModule Module { get; }
	/// <summary>
	///  Base address of the module
	/// </summary>
	public IntPtr ModuleBaseAddress { get; }

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

	/// <summary>
	///  Array of Byte pattern scan. Allows scanning for an exact array of bytes with wildcard support.
	///  Note: Partial wildcards are not supported and will be converted into full wildcards. This has a
	///  small possibility of resulting in more matches than desired. (e.g. AB ?1 turns into AB ??)
	/// </summary>
	/// <param name="pattern">
	///  The pattern of bytes to look for. Bytes are separated by spaces.
	///  Wildcards (?? symbols) are supported.
	/// </param>
	/// <example>
	///  <code>
	///  var addresses = AoBScan("03 AD FF ?? ?? ?? 4D");
	///  // Returns a list of addresses found (if any) matching the pattern.
	/// </code>
	/// </example>
	/// <returns></returns>
	public List<IntPtr> AoBScan(string pattern)
	{
		// Ensure capitalization
		pattern = pattern.ToUpper();
		// Get min & max addresses

		GetSystemInfo(out var sysInfo);

		var procMinAddress = sysInfo.minimumApplicationAddress;
		var procMaxAddress = sysInfo.maximumApplicationAddress;

		Int64 procMinAddressL = (long)procMinAddress;
		Int64 procMaxAddressL = (long)procMaxAddress;

		Int32[] intBytes = transformBytes(pattern);

		var ret = new List<IntPtr>();
		while (procMinAddressL < procMaxAddressL)
		{
			// 48 = sizeof(MEMORY_BASIC_INFORMATION)
			VirtualQueryEx(ProcessHandle, procMinAddress, out var memBasicInfo, 48);

			// Check to see if chunk is accessible
			if (memBasicInfo.Protect == PAGE_READWRITE && memBasicInfo.State == MEM_COMMIT)
			{
				var shared = ArrayPool<byte>.Shared;
				byte[] buffer = shared.Rent((int)memBasicInfo.RegionSize);

				unsafe
				{
					fixed (byte* bp = buffer)
					{
						ReadProcessMemory(ProcessHandle, new IntPtr((long)memBasicInfo.BaseAddress), bp,
							(int)memBasicInfo.RegionSize, out int _);
					}
				}

				var results = new List<IntPtr>();

				for (int i = 0; i < (int)memBasicInfo.RegionSize; i++)
				{
					for (int j = 0; j < intBytes.Length; j++)
					{
						if (intBytes[j] != -1 && intBytes[j] != buffer[i + j])
						{
							break;
						}

						if ((j + 1) == intBytes.Length)
						{
							var result = new IntPtr(i + (long)memBasicInfo.BaseAddress);
							results.Add(result);
						}
					}
				}

				ret.AddRange(results);
				shared.Return(buffer);
			}

			procMinAddressL += (long)memBasicInfo.RegionSize;
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
				new(@"\?[0-9]"),
				new(@"[0-9]\?")
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
	///  Resolves the address from a MultiLevelPtr.
	///  <returns>
	///   The memory address that results from the end of the pointer chain.
	///   Call ReadMemory on this address to retrieve the value located
	///   at this address.
	///  </returns>
	///  <example>
	///   <code>
	/// var mem = new MemoryModule("MyApplication");
	/// // Assuming the resulting value at this offset is an Int32.
	/// int[] myItemOffsets = { 0xABCD, 0xA, 0xB, 0xC };
	/// int myItemAddress = mem.GetAddressFromMlPtr(new MultiLevelPtr(mem.ModuleBaseAddress, myItemOffsets));
	/// var value = mem.ReadMemory&lt;int&gt;(myItemAddress);
	/// </code>
	///  </example>
	/// </summary>
	public IntPtr GetAddressFromMlPtr(MultiLevelPtr mlPtr)
	{
		if (mlPtr.Chain.Offsets == null)
		{
			return mlPtr.Chain.Base;
		}

		// Read whatever value is located at the baseAddress. This is our new address.
		long res = (long)mlPtr.Chain.Base;
		foreach (var offset in mlPtr.Chain.Offsets)
		{
			var nextAddress = new IntPtr(res + (long)offset);
			if (offset == mlPtr.Chain.Offsets.ElementAt(mlPtr.Chain.Offsets.Count - 1))
			{
				// Return address of item we're longerested in.
				// Returning a ReadMemory here would result in the value of the item.
				return nextAddress;
			}

			// Keep looking for address
			res = ReadMemory<int>(new IntPtr(res + (long)offset));
		}

		return new IntPtr(res);
	}

	/// <summary>
	///  Resolves the value from the address found from mlPtr
	/// </summary>
	/// <param name="mlPtr">The MultiLevelPtr to read from</param>
	/// <typeparam name="T">The type of data to read from the address resolved from the MultiLevelPtr.</typeparam>
	/// <returns>Value found from the resolved MultiLevelPtr</returns>
	public T GetValueFromMlPtr<T>(MultiLevelPtr mlPtr) where T : struct => ReadMemory<T>(GetAddressFromMlPtr(mlPtr));
}