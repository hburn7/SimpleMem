using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

// ReSharper disable UnusedMember.Local
namespace SimpleMem;

//
#pragma warning disable CS0649
internal struct MEMORY_BASIC_INFORMATION
{
	internal ulong BaseAddress;
	internal ulong AllocationBase;
	internal uint AllocationProtect;
	internal uint __alignment1;
	internal ulong RegionSize;
	internal uint State;
	internal uint Protect;
	internal uint Type;
	internal uint __alignment2;
}

internal struct SYSTEM_INFO
{
	internal ushort processorArchitecture;
	internal ushort reserved;
	internal uint pageSize;
	internal IntPtr minimumApplicationAddress;
	internal IntPtr maximumApplicationAddress;
	internal IntPtr activeProcessorMask;
	internal uint numberOfProcessors;
	internal uint processorType;
	internal uint allocationGranularity;
	internal ushort processorLevel;
	internal ushort processorRevision;
}
#pragma warning restore CS0649

/// <summary>
///  Access level to open a process with
/// </summary>
[Flags]
public enum AccessLevel
{
	/// <summary>
	///  Required to read memory in a process
	/// </summary>
	READ = 0x0010,
	/// <summary>
	///  Required to write to memory in a process
	/// </summary>
	WRITE = 0x0020,
	/// <summary>
	///  Required to perform an operation on the address space of a process.
	/// </summary>
	OPERATION = 0x0008,
	/// <summary>
	///  Required to retrieve certain information about a process, such as its token, exit code, and priority class
	/// </summary>
	QUERY_INFORMATION = 0x0400,
	/// <summary>
	///  All possible access rights for a process (that are necessary to read/write memory)
	/// </summary>
	ALL_ACCESS = READ | WRITE | OPERATION | QUERY_INFORMATION
}

/// <summary>
///  Class for cross-architecture memory manipulation.
/// </summary>
public class Memory
{
	private const int PROCESS_QUERY_INFORMATION = 0x0400;
	private const int PROCESS_WM_READ = 0x0010;
	private const int MEM_COMMIT = 0x00001000;
	private const int PAGE_EXECUTE_READWRITE = 0x40;
	private const int PAGE_EXECUTE_READ = 0x20;
	private const int PAGE_READ_WRITE = 0x04;
	private const int PAGE_READONLY = 0x02;
	private readonly string _moduleName;

	/// <summary>
	///  Opens a handle to the given processName at the provided moduleName.
	///  For example, if I have a process named "FTLGame" and my desired base address
	///  is located at "FTLGame.exe" + 0xABCD..., the processName would be "FTLGame" and
	///  the moduleName would be "FTLGame.exe".
	/// </summary>
	/// <param name="processName">
	///  The name of the process. Use <see cref="GetProcessList" />
	///  and find your process name if unsure. That value can be passed in as this parameter.
	/// </param>
	/// <param name="moduleName">
	///  The name of the module to use as the base pointer. This defaults to your
	///  application's executable if left null.
	/// </param>
	/// <param name="accessLevel">
	///  The desired access level.
	///  The minimum required for reading is AccessLevel.READ and the minimum required
	///  for writing is AccessLevel.WRITE | AccessLevel.OPERATION.
	///  AccessLevel.ALL_ACCESS gives full read-write access to the process.
	/// </param>
	public Memory(string processName, string? moduleName = null, AccessLevel accessLevel = AccessLevel.ALL_ACCESS)
	{
		Process = GetProcess(processName);
		ProcessAccessLevel = accessLevel;
		ProcessHandle = OpenProcess((int)ProcessAccessLevel, false, Process.Id);

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
	///  The user-defined desired access level for which the process was opened under.
	/// </summary>
	public AccessLevel ProcessAccessLevel { get; }
	/// <summary>
	///  The current process
	/// </summary>
	public Process Process { get; }
	/// <summary>
	///  Pointer to the handle of the opened process in memory.
	/// </summary>
	public IntPtr ProcessHandle { get; }
	/// <summary>
	///  The size of pointers for this process.
	/// </summary>
	public int PtrSize { get; } = IntPtr.Size;
	/// <summary>
	///  Module assosciated with the provided moduleName, or the process's MainModule by default.
	/// </summary>
	public ProcessModule Module { get; }
	/// <summary>
	///  Base address of the module
	/// </summary>
	public IntPtr ModuleBaseAddress { get; }
	/// <summary>
	///  ModuleBaseAddress in hex form. Casting ModuleBaseAddress .ToString() directly returns a base-10 number.
	/// </summary>
	public string ModuleBaseAddressHex => ModuleBaseAddress.ToString("X");

	[DllImport("kernel32.dll")]
	private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

	[DllImport("kernel32.dll")]
	private static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern int VirtualQueryEx(IntPtr hProcess,
		IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

	[DllImport("kernel32.dll")]
	private static extern unsafe bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
		byte* lpBuffer, int dwSize, out int lpBytesRead);

	[DllImport("kernel32.dll")]
	private static extern unsafe bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
		char* lpBuffer, int dwSize, out int lpBytesRead);

	[DllImport("kernel32.dll")]
	private static extern unsafe bool WriteProcessMemory(IntPtr hProcess,
		IntPtr lpBaseAddress, [Out] byte* lpBuffer, int dwSize, out int lpNumberOfBytesWritten);

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
	///  Gets the process (if possible) based on the class's processName.
	/// </summary>
	/// <exception cref="IndexOutOfRangeException">Thrown if the process is not found.</exception>
	/// <returns></returns>
	protected Process GetProcess(string processName)
	{
		while (true)
		{
			try
			{
				var proc = Process.GetProcessesByName(processName)[0];
				Console.WriteLine($"Process {processName} found!");

				return proc;
			}
			catch (IndexOutOfRangeException)
			{
				throw new IndexOutOfRangeException($"Process {processName} not found.");
			}
		}
	}

	/// <summary>
	///  Overwrites the value at lpBaseAddress with the provided value.
	/// </summary>
	/// <param name="lpBaseAddress">The address in memory to write to</param>
	/// <param name="value">The value to write</param>
	/// <returns>The number of bytes written</returns>
	public int WriteMemory<T>(IntPtr lpBaseAddress, T value) where T : struct
	{
		Span<byte> buffer = stackalloc byte[Unsafe.SizeOf<T>()];
		MemoryMarshal.Write(buffer, ref value);

		unsafe
		{
			fixed (byte* bp = buffer)
			{
				WriteProcessMemory(ProcessHandle, lpBaseAddress, bp, buffer.Length, out int bytesWritten);
				return bytesWritten;
			}
		}
	}

	/// <summary>
	///  Writes a string to the given address. If the length of value is longer than
	///  the maximum length of the string supported by the process at lpBaseAddress,
	///  the contents of value will overflow into subsequent addresses and will be
	///  truncated by <see cref="ReadString" />.
	/// </summary>
	/// <example>
	///  <code>
	///  IntPtr addr = new IntPtr(0xabcd);
	///  var mem = new Memory("MyGame");
	///  mem.WriteString(addr, "abc"); // Overwrites value at addr with "abc\0".
	///  mem.WriteString(addr, "abc", false); // Overwrites first 3 chars at addr with "abc". Other characters are left untouched.
	///  </code>
	/// </example>
	/// <param name="lpBaseAddress">The address in memory to write to</param>
	/// <param name="value">The string to write</param>
	/// <param name="isNullTerminated">
	///  Whether the written string should be null terminated.
	///  If false, the value written will overwrite chars beginning from lpBaseAddress through
	///  the end of value. See the example for more info.
	/// </param>
	/// <param name="encoding">The encoding to write the string in. UTF-8 by default.</param>
	/// <returns>Number of bytes written</returns>
	public int WriteMemory(IntPtr lpBaseAddress, string value, bool isNullTerminated = true, Encoding? encoding = null)
	{
		encoding ??= Encoding.UTF8;

		if (isNullTerminated)
		{
			value += "\0";
		}

		Span<byte> buffer = encoding.GetBytes(value);
		unsafe
		{
			fixed (byte* bp = buffer)
			{
				WriteProcessMemory(ProcessHandle, lpBaseAddress, bp, buffer.Length, out int bytesWritten);
				return bytesWritten;
			}
		}
	}

	/// <summary>
	///  Reads memory of the desired type from lpBaseAddress.
	/// </summary>
	/// <param name="lpBaseAddress">The address to read from</param>
	/// <typeparam name="T">The type of data to read</typeparam>
	/// <returns>The value read from lpBaseAddress</returns>
	/// <exception cref="InvalidOperationException">Type specified could not be read</exception>
	public T ReadMemory<T>(IntPtr lpBaseAddress) where T : struct
	{
		Span<byte> buffer = stackalloc byte[Unsafe.SizeOf<T>()];
		unsafe
		{
			fixed (byte* bp = buffer)
			{
				ReadProcessMemory(ProcessHandle, lpBaseAddress, bp, buffer.Length, out int _);
			}
		}

		if (MemoryMarshal.TryRead(buffer, out T res))
		{
			return res;
		}

		throw new InvalidOperationException($"Failed to read memory in the form of {typeof(T)}.");
	}

	/// <summary>
	///  Read memory from lpBaseAddress into the given buffer. The amount of
	///  memory read (in bytes) equates to the length of the buffer.
	/// </summary>
	/// <param name="lpBaseAddress">The address to read from</param>
	/// <param name="buffer">The buffer to fill with read data</param>
	/// <returns>
	///  Number of bytes read
	/// </returns>
	public int ReadMemory(IntPtr lpBaseAddress, ReadOnlySpan<byte> buffer)
	{
		unsafe
		{
			fixed (byte* bp = buffer)
			{
				ReadProcessMemory(ProcessHandle, lpBaseAddress, bp, buffer.Length, out int bytesRead);
				return bytesRead;
			}
		}
		// BUG: the memory needs to be paged and looped through if sizeBytes is too large as RPM has a size limit.
	}

	/// <summary>
	///  Read memory from lpBaseAddress into the given buffer. The amount of
	///  memory read (in bytes) equates to the length of the buffer.
	/// </summary>
	/// <param name="lpBaseAddress">The address to read from</param>
	/// <param name="buffer">The buffer to fill with read data</param>
	/// <returns>
	///  Number of bytes read
	/// </returns>
	public int ReadMemory(IntPtr lpBaseAddress, ReadOnlyMemory<byte> buffer)
	{
		unsafe
		{
			fixed (byte* bp = buffer.Span)
			{
				ReadProcessMemory(ProcessHandle, lpBaseAddress, bp, buffer.Length, out int bytesRead);
				return bytesRead;
			}
		}
		// BUG: the memory needs to be paged and looped through if sizeBytes is too large as RPM has a size limit.
	}

	/// <summary>
	///  Reads the specified number of bytes from lpBaseAddress in the specified encoding.
	///  The string is expected to start at the provided address. The user is not expected to know
	///  the length of the string obtained.
	/// </summary>
	/// <param name="lpBaseAddress">The address to read from</param>
	/// <param name="size">The maximum size of the string in bytes</param>
	/// <param name="isNullTerminated">
	///  Whether or not to return the first null-terminated string found.
	///  If false, returns a string containing the first (size) bytes beginning from lpBaseAddress.
	///  For example, if false and size is 255, returns a string with 255 bytes of character data
	///  beginning from lpBaseAddress.
	/// </param>
	/// <param name="encoding">The encoding to process the read string through. UTF-8 by default.</param>
	/// <returns>The first string read from lpBaseAddress in UTF-8 encoding, unless otherwise specified.</returns>
	/// <exception cref="InvalidOperationException">A string could not be read from the address.</exception>
	public string ReadString(IntPtr lpBaseAddress, int size = 255, bool isNullTerminated = true, Encoding? encoding = null)
	{
		encoding ??= Encoding.UTF8;

		ReadOnlySpan<byte> buffer = stackalloc byte[size];
		if (ReadMemory(lpBaseAddress, buffer) > 0)
		{
			return isNullTerminated ? encoding.GetString(buffer).Split('\0')[0] : encoding.GetString(buffer)[..size];
		}

		throw new InvalidOperationException("Failed to read string.");
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
	[SuppressMessage("ReSharper", "AccessToModifiedClosure")]
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

		int[] intBytes = transformBytes(pattern);

		var ret = new List<IntPtr>();
		while (procMinAddressL < procMaxAddressL)
		{
			// 48 = sizeof(MEMORY_BASIC_INFORMATION)
			VirtualQueryEx(ProcessHandle, procMinAddress, out var memBasicInfo, 48);

			int CHUNK_SZ;
			if (memBasicInfo.RegionSize > int.MaxValue)
			{
				CHUNK_SZ = int.MaxValue / 2;
			}
			else
			{
				CHUNK_SZ = Math.Min(int.MaxValue / 2, (int)memBasicInfo.RegionSize);
			}

			// Check to see if chunk is accessible
			if (memBasicInfo.Protect is PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_READ
				    or PAGE_READONLY or PAGE_READ_WRITE &&
			    memBasicInfo.State == MEM_COMMIT)
			{
				var shared = ArrayPool<byte>.Shared;
				byte[] buffer = shared.Rent(CHUNK_SZ);

				unsafe
				{
					fixed (byte* bp = buffer)
					{
						ReadProcessMemory(ProcessHandle, new IntPtr((long)memBasicInfo.BaseAddress), bp,
							CHUNK_SZ, out int _);
					}
				}

				var results = new List<IntPtr>();

				for (long i = 0; i < CHUNK_SZ; i++)
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

			procMinAddressL += CHUNK_SZ;
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
	///   The memory address that results from the end of the pointer
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
	public IntPtr ReadAddressFromMlPtr(MultiLevelPtr mlPtr)
	{
		var baseRead = new IntPtr((long)ModuleBaseAddress + (long)mlPtr.Base);

		// Read whatever value is located at the baseAddress. This is our new address.
		long res;
		bool readLong;
		
		if ((long)baseRead > int.MaxValue)
		{
			res = ReadMemory<long>(baseRead);
			readLong = true;
		}
		else
		{
			res = ReadMemory<int>(baseRead);
			readLong = false;
		}

		if (!mlPtr.Offsets.Any())
		{
			return new IntPtr(res);
		}

		foreach (var offset in mlPtr.Offsets)
		{
			var nextAddress = new IntPtr(res + (long)offset);
			if (offset == mlPtr.Offsets[^1])
			{
				// Return address of item we're interested in.
				// Returning a ReadMemory here would result in the value of the item.
				return nextAddress;
			}

			// Keep looking for address
			if (readLong)
			{
				res = ReadMemory<long>(nextAddress);
			}
			else
			{
				res = ReadMemory<int>(nextAddress);
			}
		}

		return new IntPtr(res);
	}

	/// <summary>
	///  Resolves the value from the address found from mlPtr
	/// </summary>
	/// <param name="mlPtr">The MultiLevelPtr to read from</param>
	/// <typeparam name="T">The type of data to read from the address resolved from the MultiLevelPtr.</typeparam>
	/// <returns>Value found from the resolved MultiLevelPtr</returns>
	public T ReadValueFromMlPtr<T>(MultiLevelPtr mlPtr) where T : struct => ReadMemory<T>(ReadAddressFromMlPtr(mlPtr));

	/// <summary>
	///  Resolves the value from the address found from mlPtr
	/// </summary>
	/// <param name="mlPtr">The MultiLevelPtr to read from</param>
	/// <typeparam name="T">The type associated with the given MultiLevelPtr.</typeparam>
	/// <returns>Value found from the resolved MultiLevelPtr</returns>
	public T ReadValueFromMlPtr<T>(MultiLevelPtr<T> mlPtr) where T : struct => ReadMemory<T>(ReadAddressFromMlPtr(mlPtr));

	/// <summary>
	///  Reads a string from the address found from mlPtr.
	///  <inheritdoc cref="ReadString" />
	/// </summary>
	/// <param name="mlPtr">The MultiLevelPtr to read from</param>
	/// <param name="size">The maximum size of the string in bytes</param>
	/// <param name="isNullTerminated">
	///  Whether or not to return the first null-terminated string found.
	///  If false, returns a string containing the first (size) bytes beginning from lpBaseAddress.
	///  For example, if false and size is 255, returns a string with 255 bytes of character data
	///  beginning from lpBaseAddress.
	/// </param>
	/// <param name="encoding">The encoding to process the read string through. UTF-8 by default.</param>
	/// <returns>The first string read from lpBaseAddress in UTF-8 encoding, unless otherwise specified.</returns>
	public string ReadStringFromMlPtr(MultiLevelPtr mlPtr, int size = 255, bool isNullTerminated = true,
		Encoding? encoding = null) => ReadString(ReadAddressFromMlPtr(mlPtr), size, isNullTerminated, encoding);

#region Supplemental Methods
	/// <summary>
	///  Returns a list of all currently running executables' process names (regardless of architecture).
	///  The names of these processes can be used as the processName <see cref="Memory" /> constructor argument.
	/// </summary>
	public static List<string> GetProcessList()
	{
		var ls = new List<string>();
		var processCollection = Process.GetProcesses();
		foreach (var p in processCollection)
		{
			ls.Add(p.ProcessName);
		}

		return ls;
	}

	/// <summary>
	///  Prints all currently running executables' process names to the console.
	/// </summary>
	public static void PrintProcessList()
	{
		foreach (string p in GetProcessList())
		{
			Console.WriteLine(p);
		}
	}
#endregion
}