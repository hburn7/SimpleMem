using System.Text;

namespace SimpleMem;

/// <summary>
///  Class for conveniently definining multi-level pointers.
///  Multi-level pointers are used for obtaining values even
///  after restarts of programs (unlike a single,
///  non-static memory address).
///  <example>
///   Consider a game called "MyGame" with a module of "MyGame.exe".
///   "MyGame.exe" is given a memory address that changes with each
///   launch of the program, but all of the values desired (such as
///   gold, points, exp, etc.) lay the same distance away in memory
///   from the module. Say the offset for gold is 0xC and exp is 0xD.
///   A MultiLevelPtr can be created from the "base address" of the module
///   with the offsets being 0xC for gold and 0xD for exp. Assuming the
///   base address and offsets are correct, the desired values will
///   always be returned.
///  </example>
/// </summary>
public class MultiLevelPtr
{
	/// <summary>
	///  <inheritdoc cref="MultiLevelPtr" />
	/// </summary>
	/// <param name="lpBaseAddress">The address the pointer starts from. This is almost always the ModuleBaseAddress.</param>
	/// <param name="offsets">The offsets needed to decipher the chain</param>
	public MultiLevelPtr(IntPtr lpBaseAddress, params IntPtr[] offsets)
	{
		if (!offsets.Any())
		{
			Base = lpBaseAddress;
		}
		else
		{
			Base = lpBaseAddress;
			Offsets = offsets.ToList();
		}
	}

	/// <summary>
	///  <inheritdoc cref="MultiLevelPtr" />
	/// </summary>
	/// <param name="lpBaseAddress">The address the pointer starts from. This is almost always the ModuleBaseAddress.</param>
	/// <param name="offsets">The offsets needed to decipher the chain</param>
	public MultiLevelPtr(IntPtr lpBaseAddress, params int[] offsets)
	{
		Base = lpBaseAddress;

		if (!offsets.Any())
		{
			return;
		}

		Offsets = ConvertInts(offsets);
	}

	/// <summary>
	///  <inheritdoc cref="MultiLevelPtr" />
	///  Creates a multi level pointer from an existing one, then adds
	///  the provided offsets to the old baseMlPtr's offsets list.
	/// </summary>
	/// <param name="baseMlPtr">The previous MultiLevelPtr to base this one from</param>
	/// <param name="offsets">Collection of offsets to append to the old base offsets</param>
	public MultiLevelPtr(MultiLevelPtr baseMlPtr, params int[] offsets)
	{
		Base = baseMlPtr.Base;

		if (baseMlPtr.Offsets.Any())
		{
			foreach (var offset in baseMlPtr.Offsets)
			{
				Offsets.Add(offset);
			}
		}

		if (!offsets.Any())
		{
			return;
		}

		foreach (int offset in offsets)
		{
			Offsets.Add(new IntPtr(offset));
		}
	}

	/// <summary>
	///  <inheritdoc cref="MultiLevelPtr" />
	///  Creates a multi level pointer from an existing one, then adds
	///  the provided offsets to the old baseMlPtr's offsets list.
	/// </summary>
	/// <param name="baseMlPtr">The previous MultiLevelPtr to base this one from</param>
	/// <param name="offsets">Collection of offsets to append to the old base offsets</param>
	public MultiLevelPtr(MultiLevelPtr baseMlPtr, params long[] offsets)
	{
		Base = baseMlPtr.Base;

		if (baseMlPtr.Offsets.Any())
		{
			foreach (var offset in baseMlPtr.Offsets)
			{
				Offsets.Add(offset);
			}
		}

		if (!offsets.Any())
		{
			return;
		}

		foreach (long offset in offsets)
		{
			Offsets.Add(new IntPtr(offset));
		}
	}

	/// <summary>
	///  <inheritdoc cref="MultiLevelPtr" />
	/// </summary>
	/// <param name="lpBaseAddress">The address the pointer starts from. This is almost always the ModuleBaseAddress.</param>
	/// <param name="offsets">The offsets needed to decipher the chain</param>
	public MultiLevelPtr(long lpBaseAddress, params int[] offsets)
	{
		Base = new IntPtr(lpBaseAddress);

		if (!offsets.Any())
		{
			return;
		}

		Offsets = ConvertInts(offsets);
	}

	/// <summary>
	///  <inheritdoc cref="MultiLevelPtr" />
	/// </summary>
	/// <param name="pointers">A chain of pointers to resolve</param>
	public MultiLevelPtr(IntPtr[] pointers)
	{
		Base = pointers[0];
		Offsets = pointers[1..];
	}

	/// <summary>
	///  <inheritdoc cref="MultiLevelPtr" />
	/// </summary>
	/// <param name="pointers">A chain of pointers to resolve</param>
	public MultiLevelPtr(int[] pointers)
	{
		Base = new IntPtr(pointers[0]);
		Offsets = ConvertInts(pointers[1..]);
	}

	/// <summary>
	///  <inheritdoc cref="MultiLevelPtr" />
	/// </summary>
	/// <param name="pointers">A chain of pointers to resolve</param>
	public MultiLevelPtr(long[] pointers)
	{
		Base = new IntPtr(pointers[0]);
		Offsets = ConvertLongs(pointers[1..]);
	}

	/// <summary>
	///  Base address of the pointer chain
	/// </summary>
	public IntPtr Base { get; set; }
	/// <summary>
	///  Optional list of offsets containing pointer offsets (from the provided base).
	/// </summary>
	public IList<IntPtr> Offsets { get; set; } = new List<IntPtr>();

	/// <inheritdoc />
	public override string ToString()
	{
		var sb = new StringBuilder($"MultiLevelPtr(Base={Base:X}, Offsets=[");
		foreach (var offset in Offsets)
		{
			sb.Append($"{offset:X}, ");
		}

		sb.Remove(sb.Length - 2, 2);
		sb.Append("])");
		return sb.ToString();
	}

	private static IList<IntPtr> ConvertInts(int[] ints)
	{
		var n = new List<IntPtr>(ints.Length);
		foreach (int i in ints)
		{
			n.Add(new IntPtr(i));
		}

		return n;
	}

	private static IList<IntPtr> ConvertLongs(long[] ints)
	{
		var n = new List<IntPtr>(ints.Length);
		foreach (long i in ints)
		{
			n.Add(new IntPtr(i));
		}

		return n;
	}
}

/// <summary>
///  Class for conveniently definining multi-level pointers.
///  Multi-level pointers are used for obtaining values even
///  after restarts of programs (unlike a single,
///  non-static memory address).
///  <example>
///   Consider a game called "MyGame" with a module of "MyGame.exe".
///   "MyGame.exe" is given a memory address that changes with each
///   launch of the program, but all of the values desired (such as
///   gold, points, exp, etc.) lay the same distance away in memory
///   from the module. Say the offset for gold is 0xC and exp is 0xD.
///   A MultiLevelPtr can be created from the "base address" of the module
///   with the offsets being 0xC for gold and 0xD for exp. Assuming the
///   base address and offsets are correct, the desired values will
///   always be returned.
///  </example>
/// </summary>
/// <typeparam name="T">The expected type resolved from the MultiLevelPtr</typeparam>
public class MultiLevelPtr<T> : MultiLevelPtr where T : struct
{
	/// <inheritdoc />
	public MultiLevelPtr(IntPtr lpBaseAddress, params IntPtr[] offsets) : base(lpBaseAddress, offsets) {}

	/// <inheritdoc />
	public MultiLevelPtr(IntPtr lpBaseAddress, params int[] offsets) : base(lpBaseAddress, offsets) {}

	/// <inheritdoc />
	public MultiLevelPtr(MultiLevelPtr baseMlPtr, params int[] offsets) : base(baseMlPtr, offsets) {}

	/// <inheritdoc />
	public MultiLevelPtr(MultiLevelPtr baseMlPtr, params long[] offsets) : base(baseMlPtr, offsets) {}

	/// <inheritdoc />
	public MultiLevelPtr(long lpBaseAddress, params int[] offsets) : base(lpBaseAddress, offsets) {}

	/// <inheritdoc />
	public MultiLevelPtr(IntPtr[] pointers) : base(pointers) {}

	/// <inheritdoc />
	public MultiLevelPtr(int[] pointers) : base(pointers) {}

	/// <inheritdoc />
	public MultiLevelPtr(long[] pointers) : base(pointers) {}
}

/// <summary>
/// Extensions for Memory
/// </summary>
public static class MemoryExtensions
{
	/// <summary>
	/// Extension that serves as a wrapper for mem.ModuleBaseAddress + offset.
	/// Useful for storing lots of static offsets that derive directly from
	/// the ModuleBaseAddress (these are not the same as pointers, although they are similar).
	/// </summary>
	/// <param name="mem">The memory instance in which the base address exists</param>
	/// <param name="offset">Any address</param>
	/// <returns></returns>
	public static IntPtr StaticOffset(this Memory mem, int offset) => mem.ModuleBaseAddress + offset;
	/// <inheritdoc cref="StaticOffset(SimpleMem.Memory,int)"/> 
	public static IntPtr StaticOffset(this Memory mem, long offset) => new IntPtr((long) mem.ModuleBaseAddress + offset);
}

/// <summary>
/// Extensions for MultiLevelPtr
/// </summary>
public static class PointerExtensions
{
	/// <summary>
	///  Reads the value, in memory, of this <see cref="MultiLevelPtr{T}" />. This extension saves
	///  a separate call to <see cref="Memory.ReadAddressFromMlPtr" />.
	/// </summary>
	/// <param name="mlPtr">The <see cref="MultiLevelPtr{T}" /> to read the value from</param>
	/// <param name="mem">The <see cref="Memory" /> instance in which this value lays</param>
	/// <returns></returns>
	public static T ReadValue<T>(this MultiLevelPtr<T> mlPtr, Memory mem) where T : struct => mem.ReadValueFromMlPtr(mlPtr);

	/// <summary>
	/// Writes the value in the same fashion as <see cref="Memory.WriteMemory{T}"/>
	/// </summary>
	public static int WriteValue<T>(this MultiLevelPtr<T> mlPtr, Memory mem, T val) where T : struct 
		=> mem.WriteMemory(mlPtr.GetAddress(mem), val);

	/// <summary>
	/// Writes the bytes to memory at the address resolved from the MultiLevelPtr.
	/// </summary>
	/// <returns>The number of bytes written</returns>
	public static int WriteBytes(this MultiLevelPtr mlPtr, Memory mem, params byte[] bytes) =>
		mem.WriteMemory(mlPtr.GetAddress(mem), bytes);

	/// <summary>
	///  Gets the address resolved from the given mlPtr.
	/// </summary>
	/// <param name="mlPtr">The <see cref="MultiLevelPtr" /> to read the address from</param>
	/// <param name="mem">The <see cref="Memory" /> instance in which this address lays</param>
	/// <returns>A IntPtr containing the address, if found.</returns>
	public static IntPtr GetAddress(this MultiLevelPtr mlPtr, Memory mem) => mem.ReadAddressFromMlPtr(mlPtr);
}