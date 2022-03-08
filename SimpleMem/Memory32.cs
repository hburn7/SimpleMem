using System.Runtime.InteropServices;
using System.Text;

namespace SimpleMem;

/// <summary>
///  Class for manipulating memory in 32-bit processes.
/// </summary>
public class Memory32 : Memory
{
	/// <summary>
	///  Manipulate 32-bit processes by passing in a running 32-bit executable's
	///  process name and module name.
	/// </summary>
	/// <param name="processName">
	///  The name of the process. Use <see cref="Memory.GetProcessList" />
	///  and find your process name if unsure. That value can be passed in as this parameter.
	/// </param>
	/// <param name="accessLevel">The desired access level.
	/// The minimum required for reading is AccessLevel.READ and the minimum required
	/// for writing is AccessLevel.WRITE | AccessLevel.OPERATION.
	/// AccessLevel.ALL_ACCESS gives full read-write access to the process.</param>
	public Memory32(string processName, AccessLevel accessLevel = AccessLevel.ALL_ACCESS) : base(processName, accessLevel)
	{
		ProcessHandleInt32 = ProcessHandle.ToInt32();
	}

	private Int32 ProcessHandleInt32 { get; }

	[DllImport("kernel32.dll")]
	protected internal static extern bool ReadProcessMemory(Int32 hProcess,
		Int32 lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

	[DllImport("kernel32.dll")]
	protected internal static extern bool WriteProcessMemory(Int32 hProcess,
		Int32 lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesWritten);

	/// <summary>
	///  Overwrites the value at lpBaseAddress with the provided value.
	/// </summary>
	/// <param name="lpBaseAddress">The address in memory to write to</param>
	/// <param name="value">The value to write</param>
	/// <returns>The number of bytes written</returns>
	public int WriteMemory(Int32 lpBaseAddress, byte[] value)
	{
		int bytesWritten = 0;
		WriteProcessMemory(ProcessHandleInt32, lpBaseAddress, value, value.Length, ref bytesWritten);
		return bytesWritten;
	}

	/// <summary>
	///  Overwrites the value at lpBaseAddress with the provided value.
	/// </summary>
	/// <param name="lpBaseAddress">The address in memory to write to</param>
	/// <param name="value">The value to write</param>
	/// <returns>The number of bytes written</returns>
	public int WriteMemory(Int32 lpBaseAddress, Int16 value)
	{
		int bytesWritten = 0;
		byte[] buffer = BitConverter.GetBytes(value);
		WriteProcessMemory(ProcessHandleInt32, lpBaseAddress, buffer, buffer.Length, ref bytesWritten);
		return bytesWritten;
	}

	/// <summary>
	///  Overwrites the value at lpBaseAddress with the provided value.
	/// </summary>
	/// <param name="lpBaseAddress">The address in memory to write to</param>
	/// <param name="value">The value to write</param>
	/// <returns>The number of bytes written</returns>
	public int WriteMemory(Int32 lpBaseAddress, Int32 value)
	{
		int bytesWritten = 0;
		byte[] buffer = BitConverter.GetBytes(value);
		WriteProcessMemory(ProcessHandleInt32, lpBaseAddress, buffer, buffer.Length, ref bytesWritten);
		return bytesWritten;
	}

	/// <summary>
	///  Overwrites the value at lpBaseAddress with the provided value.
	/// </summary>
	/// <param name="lpBaseAddress">The address in memory to write to</param>
	/// <param name="value">The value to write</param>
	/// <returns>The number of bytes written</returns>
	public int WriteMemory(Int32 lpBaseAddress, Int64 value)
	{
		int bytesWritten = 0;
		byte[] buffer = BitConverter.GetBytes(value);
		WriteProcessMemory(ProcessHandleInt32, lpBaseAddress, buffer, buffer.Length, ref bytesWritten);
		return bytesWritten;
	}

	/// <summary>
	///  Overwrites the value at lpBaseAddress with the provided value.
	/// </summary>
	/// <param name="lpBaseAddress">The address in memory to write to</param>
	/// <param name="value">The value to write</param>
	/// <returns>The number of bytes written</returns>
	public int WriteMemory(Int32 lpBaseAddress, UInt16 value)
	{
		int bytesWritten = 0;
		byte[] buffer = BitConverter.GetBytes(value);
		WriteProcessMemory(ProcessHandleInt32, lpBaseAddress, buffer, buffer.Length, ref bytesWritten);
		return bytesWritten;
	}

	/// <summary>
	///  Overwrites the value at lpBaseAddress with the provided value.
	/// </summary>
	/// <param name="lpBaseAddress">The address in memory to write to</param>
	/// <param name="value">The value to write</param>
	/// <returns>The number of bytes written</returns>
	public int WriteMemory(Int32 lpBaseAddress, UInt32 value)
	{
		int bytesWritten = 0;
		byte[] buffer = BitConverter.GetBytes(value);
		WriteProcessMemory(ProcessHandleInt32, lpBaseAddress, buffer, buffer.Length, ref bytesWritten);
		return bytesWritten;
	}

	/// <summary>
	///  Overwrites the value at lpBaseAddress with the provided value.
	/// </summary>
	/// <param name="lpBaseAddress">The address in memory to write to</param>
	/// <param name="value">The value to write</param>
	/// <returns>The number of bytes written</returns>
	public int WriteMemory(Int32 lpBaseAddress, UInt64 value)
	{
		int bytesWritten = 0;
		byte[] buffer = BitConverter.GetBytes(value);
		WriteProcessMemory(ProcessHandleInt32, lpBaseAddress, buffer, buffer.Length, ref bytesWritten);
		return bytesWritten;
	}

	/// <summary>
	///  Overwrites the value at lpBaseAddress with the provided value.
	/// </summary>
	/// <param name="lpBaseAddress">The address in memory to write to</param>
	/// <param name="value">The value to write</param>
	/// <returns>The number of bytes written</returns>
	public int WriteMemory(Int32 lpBaseAddress, bool value)
	{
		int bytesWritten = 0;
		byte[] buffer = BitConverter.GetBytes(value);
		WriteProcessMemory(ProcessHandleInt32, lpBaseAddress, buffer, buffer.Length, ref bytesWritten);
		return bytesWritten;
	}

	/// <summary>
	///  Overwrites the value at lpBaseAddress with the provided value.
	/// </summary>
	/// <param name="lpBaseAddress">The address in memory to write to</param>
	/// <param name="value">The value to write</param>
	/// <returns>The number of bytes written</returns>
	public int WriteMemory(Int32 lpBaseAddress, float value)
	{
		int bytesWritten = 0;
		byte[] buffer = BitConverter.GetBytes(value);
		WriteProcessMemory(ProcessHandleInt32, lpBaseAddress, buffer, buffer.Length, ref bytesWritten);
		return bytesWritten;
	}

	/// <summary>
	///  Overwrites the value at lpBaseAddress with the provided value.
	/// </summary>
	/// <param name="lpBaseAddress">The address in memory to write to</param>
	/// <param name="value">The value to write</param>
	/// <returns>The number of bytes written</returns>
	public int WriteMemory(Int32 lpBaseAddress, double value)
	{
		int bytesWritten = 0;
		byte[] buffer = BitConverter.GetBytes(value);
		WriteProcessMemory(ProcessHandleInt32, lpBaseAddress, buffer, buffer.Length, ref bytesWritten);
		return bytesWritten;
	}

	/// <summary>
	///  Overwrites the value at lpBaseAddress with the provided value.
	/// </summary>
	/// <param name="lpBaseAddress">The address in memory to write to</param>
	/// <param name="value">The value to write</param>
	/// <returns>The number of bytes written</returns>
	public int WriteMemory(Int32 lpBaseAddress, char value)
	{
		int bytesWritten = 0;
		byte[] buffer = BitConverter.GetBytes(value);
		WriteProcessMemory(ProcessHandleInt32, lpBaseAddress, buffer, buffer.Length, ref bytesWritten);
		return bytesWritten;
	}

	/// <summary>
	///  Overwrites the value at lpBaseAddress with the provided value.
	/// </summary>
	/// <param name="lpBaseAddress">The address in memory to write to</param>
	/// <param name="value">The value to write</param>
	/// <returns>The number of bytes written</returns>
	public int WriteMemory(Int32 lpBaseAddress, string value)
	{
		int bytesWritten = 0;
		byte[] buffer = Encoding.UTF8.GetBytes(value);
		WriteProcessMemory(ProcessHandleInt32, lpBaseAddress, buffer, buffer.Length, ref bytesWritten);
		return bytesWritten;
	}

	/// <summary>
	///  Overwrites the value at lpBaseAddress with the provided value.
	/// </summary>
	/// <param name="lpBaseAddress">The address in memory to write to</param>
	/// <param name="value">The value to write</param>
	/// <returns>The number of bytes written</returns>
	public int WriteMemory(Int32 lpBaseAddress, Half value)
	{
		int bytesWritten = 0;
		byte[] buffer = BitConverter.GetBytes(value);
		WriteProcessMemory(ProcessHandleInt32, lpBaseAddress, buffer, buffer.Length, ref bytesWritten);
		return bytesWritten;
	}

	private byte[] ReadMemory<T>(Int32 lpBaseAddress) where T : IEquatable<T>
	{
		int bytesRead = 0;
		byte[] buffer = new byte[Marshal.SizeOf(typeof(T))];
		ReadProcessMemory(ProcessHandleInt32, lpBaseAddress, buffer, buffer.Length, ref bytesRead);
		return buffer;
	}

	/// <summary>
	///  Read memory from lpBaseAddress through whatever address is
	///  located sizeBytes away from lpBaseAddress.
	/// </summary>
	/// <param name="lpBaseAddress">32-bit memory address to start from</param>
	/// <param name="sizeBytes">The number of bytes to read through</param>
	/// <returns>
	///  Buffer containing all data from lpBaseAddress through the address
	///  located at lpBaseAddress + sizeBytes
	/// </returns>
	public byte[] ReadMemory(Int32 lpBaseAddress, int sizeBytes)
	{
		int bytesRead = 0;
		byte[] buffer = new byte[sizeBytes];
		ReadProcessMemory(ProcessHandleInt32, lpBaseAddress, buffer, buffer.Length, ref bytesRead);
		return buffer;
	}

	/// <summary>
	///  Reads a 16-bit unsigned integer from memory.
	/// </summary>
	/// <param name="lpBaseAddress">32-bit memory address to locate the value from.</param>
	/// <returns>Value at lpBaseAddress in 16-bit unsigned integer form.</returns>
	public ushort ReadMemoryUShort(Int32 lpBaseAddress)
	{
		byte[] buffer = ReadMemory<Int16>(lpBaseAddress);
		return BitConverter.ToUInt16(buffer);
	}

	/// <summary>
	///  Reads a 32-bit unsigned integer from memory.
	/// </summary>
	/// <param name="lpBaseAddress">32-bit memory address to locate the value from.</param>
	/// <returns>Value at lpBaseAddress in 32-bit unsigned integer form.</returns>
	public UInt32 ReadMemoryUInt32(Int32 lpBaseAddress)
	{
		byte[] buffer = ReadMemory<Int32>(lpBaseAddress);
		return BitConverter.ToUInt32(buffer);
	}

	/// <summary>
	///  Reads a 64-bit unsigned integer from memory.
	/// </summary>
	/// <param name="lpBaseAddress">32-bit memory address to locate the value from.</param>
	/// <returns>Value at lpBaseAddress in 64-bit unsigned integer form.</returns>
	public UInt64 ReadMemoryUInt64(Int32 lpBaseAddress)
	{
		byte[] buffer = ReadMemory<Int64>(lpBaseAddress);
		return BitConverter.ToUInt64(buffer);
	}

	/// <summary>
	///  Reads a 16-bit integer from memory.
	/// </summary>
	/// <param name="lpBaseAddress">32-bit memory address to locate the value from.</param>
	/// <returns>Value at lpBaseAddress in 16-bit integer form.</returns>
	public short ReadMemoryShort(Int32 lpBaseAddress)
	{
		byte[] buffer = ReadMemory<Int16>(lpBaseAddress);
		return BitConverter.ToInt16(buffer);
	}

	/// <summary>
	///  Reads a 32-bit integer from memory.
	/// </summary>
	/// <param name="lpBaseAddress">32-bit memory address to locate the value from.</param>
	/// <returns>Value at lpBaseAddress in 32-bit integer form.</returns>
	public Int32 ReadMemoryInt32(Int32 lpBaseAddress)
	{
		byte[] buffer = ReadMemory<Int32>(lpBaseAddress);
		return BitConverter.ToInt32(buffer);
	}

	/// <summary>
	///  Reads a 64-bit integer from memory.
	/// </summary>
	/// <param name="lpBaseAddress">32-bit memory address to locate the value from.</param>
	/// <returns>Value at lpBaseAddress in 64-bit integer form.</returns>
	public Int64 ReadMemoryInt64(Int32 lpBaseAddress)
	{
		byte[] buffer = ReadMemory<Int64>(lpBaseAddress);
		return BitConverter.ToInt64(buffer);
	}

	/// <summary>
	///  Reads a double-precision floating point number from memory.
	/// </summary>
	/// <param name="lpBaseAddress">32-bit memory address to locate the value from.</param>
	/// <returns>Value at lpBaseAddress in the form of a double.</returns>
	public double ReadMemoryDouble(Int32 lpBaseAddress)
	{
		byte[] buffer = ReadMemory<double>(lpBaseAddress);
		return BitConverter.ToDouble(buffer);
	}

	/// <summary>
	///  Reads a single-precision floating point number from memory.
	/// </summary>
	/// <param name="lpBaseAddress">32-bit memory address to locate the value from.</param>
	/// <returns>Value at lpBaseAddress in the form of a float.</returns>
	public float ReadMemoryFloat(Int32 lpBaseAddress)
	{
		byte[] buffer = ReadMemory<Single>(lpBaseAddress);
		return BitConverter.ToSingle(buffer);
	}

	/// <summary>
	///  Reads a string from memory.
	/// </summary>
	/// <param name="lpBaseAddress">32-bit memory address to locate the value from.</param>
	/// <returns>Value at lpBaseAddress in the form of a string.</returns>
	public string ReadMemoryString(Int32 lpBaseAddress)
	{
		byte[] buffer = ReadMemory<string>(lpBaseAddress);
		return BitConverter.ToString(buffer);
	}

	/// <summary>
	///  Reads a bool from memory.
	/// </summary>
	/// <param name="lpBaseAddress">32-bit memory address to locate the value from.</param>
	/// <returns>Value at lpBaseAddress in the form of a bool.</returns>
	public bool ReadMemoryBool(Int32 lpBaseAddress)
	{
		byte[] buffer = ReadMemory<bool>(lpBaseAddress);
		return BitConverter.ToBoolean(buffer);
	}

	/// <summary>
	///  Reads a single byte from memory.
	/// </summary>
	/// <param name="lpBaseAddress">32-bit memory address to locate the value from.</param>
	/// <returns>Value at lpBaseAddress in the form of a byte.</returns>
	public byte ReadMemoryByte(Int32 lpBaseAddress)
	{
		byte[] buffer = ReadMemory<byte>(lpBaseAddress);
		return buffer[0];
	}

	/// <summary>
	///  Reads a char from memory.
	/// </summary>
	/// <param name="lpBaseAddress">32-bit memory address to locate the value from.</param>
	/// <returns>Value at lpBaseAddress in the form of a char.</returns>
	public char ReadMemoryChar(Int32 lpBaseAddress)
	{
		byte[] buffer = ReadMemory<char>(lpBaseAddress);
		return BitConverter.ToChar(buffer);
	}
}