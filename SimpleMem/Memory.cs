using System.Diagnostics;
using System.Runtime.InteropServices;

namespace SimpleMem;

/// <summary>
/// Access level to open a process with
/// </summary>
[Flags]
public enum AccessLevel
{
	/// <summary>
	/// Required to read memory in a process
	/// </summary>
	READ = 0x0010,
	/// <summary>
	/// Required to write to memory in a process
	/// </summary>
	WRITE = 0x0020,
	/// <summary>
	/// Required to perform an operation on the address space of a process.
	/// </summary>
	OPERATION = 0x0008,
	/// <summary>
	/// All possible access rights for a process (that are necessary to read/write memory)
	/// </summary>
	ALL_ACCESS = READ | WRITE | OPERATION
}

/// <summary>
///  Base class for cross-architecture memory manipulation.
/// </summary>
public class Memory
{
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
	/// <param name="accessLevel">The desired access level.
	/// The minimum required for reading is AccessLevel.READ and the minimum required
	/// for writing is AccessLevel.WRITE | AccessLevel.OPERATION.
	/// AccessLevel.ALL_ACCESS gives full read-write access to the process.</param>
	protected Memory(string processName, AccessLevel accessLevel = AccessLevel.ALL_ACCESS)
	{
		ProcessName = processName;

		var proc = GetProcess();
		ProcessID = proc.Id;
		ProcessAccessLevel = accessLevel;
		ProcessHandle = OpenProcess((int)ProcessAccessLevel, false, ProcessID);
	}

	/// <summary>
	///  The user-defined desired access level for which the process was opened under.
	/// </summary>
	protected AccessLevel ProcessAccessLevel { get; }
	/// <summary>
	///  Process ID of the running executable.
	/// </summary>
	protected int ProcessID { get; }
	/// <summary>
	///  Process name of the running executable.
	/// </summary>
	protected string ProcessName { get; }
	/// <summary>
	///  Pointer to the handle of the process in memory.
	/// </summary>
	protected IntPtr ProcessHandle { get; }

	[DllImport("kernel32.dll")]
	private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

	/// <summary>
	///  Gets the process (if possible) based on the class's processName.
	/// </summary>
	/// <exception cref="IndexOutOfRangeException">Thrown if the process is not found.</exception>
	/// <returns></returns>
	protected Process GetProcess()
	{
		while (true)
		{
			try
			{
				var proc = Process.GetProcessesByName(ProcessName)[0];

				Console.WriteLine($"Process {ProcessName} found!");

				return proc;
			}
			catch (IndexOutOfRangeException)
			{
				throw new IndexOutOfRangeException($"Process {ProcessName} not found.");
			}
		}
	}

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
}