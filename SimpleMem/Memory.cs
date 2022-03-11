using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace SimpleMem;

public struct MEMORY_BASIC_INFORMATION
{
	public ulong BaseAddress;
	public ulong AllocationBase;
	public uint AllocationProtect;
	public uint __alignment1;
	public ulong RegionSize;
	public uint State;
	public uint Protect;
	public uint Type;
	public uint __alignment2;
}

public struct SYSTEM_INFO
{
	public ushort processorArchitecture;
	private ushort reserved;
	public uint pageSize;
	public IntPtr minimumApplicationAddress;
	public IntPtr maximumApplicationAddress;
	public IntPtr activeProcessorMask;
	public uint numberOfProcessors;
	public uint processorType;
	public uint allocationGranularity;
	public ushort processorLevel;
	public ushort processorRevision;
}

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
	protected const int MEM_COMMIT = 0x00001000;
	protected const int PAGE_READWRITE = 0x04;

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
	/// <param name="accessLevel">
	///  The desired access level.
	///  The minimum required for reading is AccessLevel.READ and the minimum required
	///  for writing is AccessLevel.WRITE | AccessLevel.OPERATION.
	///  AccessLevel.ALL_ACCESS gives full read-write access to the process.
	/// </param>
	public Memory(string processName, AccessLevel accessLevel = AccessLevel.ALL_ACCESS)
	{
		Process = GetProcess(processName);
		ProcessAccessLevel = accessLevel;
		ProcessHandle = OpenProcess((int)ProcessAccessLevel, false, Process.Id);
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

	[DllImport("kernel32.dll")]
	private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

	[DllImport("kernel32.dll")]
	protected static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

	[DllImport("kernel32.dll", SetLastError = true)]
	protected static extern int VirtualQueryEx(IntPtr hProcess,
		IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

	[DllImport("kernel32.dll")]
	protected static extern unsafe bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
		byte* lpBuffer, int dwSize, out int lpBytesRead);

	[DllImport("kernel32.dll")]
	protected static extern unsafe bool WriteProcessMemory(IntPtr hProcess,
		IntPtr lpBaseAddress, [Out] byte* lpBuffer, int dwSize, out int lpNumberOfBytesWritten);

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

#region WriteMemory
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
#endregion

#region ReadMemory
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
#endregion

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