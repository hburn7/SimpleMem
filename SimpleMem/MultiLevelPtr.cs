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
			Chain.Base = lpBaseAddress;
		}
		else
		{
			Chain.Base = lpBaseAddress;
			Chain.Offsets = offsets.ToList();
		}
	}

	/// <summary>
	///  <inheritdoc cref="MultiLevelPtr" />
	/// </summary>
	/// <param name="lpBaseAddress">The address the pointer starts from. This is almost always the ModuleBaseAddress.</param>
	/// <param name="offsets">The offsets needed to decipher the chain</param>
	public MultiLevelPtr(IntPtr lpBaseAddress, params int[] offsets)
	{
		Chain.Base = lpBaseAddress;

		if (!offsets.Any())
		{
			return;
		}

		Chain.Offsets = ConvertInts(offsets);
	}

	/// <summary>
	///  <inheritdoc cref="MultiLevelPtr" />
	/// </summary>
	/// <param name="lpBaseAddress">The address the pointer starts from. This is almost always the ModuleBaseAddress.</param>
	/// <param name="offsets">The offsets needed to decipher the chain</param>
	public MultiLevelPtr(long lpBaseAddress, params int[] offsets)
	{
		Chain.Base = new IntPtr(lpBaseAddress);

		if (!offsets.Any())
		{
			return;
		}

		Chain.Offsets = ConvertInts(offsets);
	}

	/// <summary>
	///  <inheritdoc cref="MultiLevelPtr" />
	/// </summary>
	/// <param name="pointers">A chain of pointers to resolve</param>
	public MultiLevelPtr(IntPtr[] pointers)
	{
		Chain.Base = pointers[0];
		Chain.Offsets = pointers[1..];
	}

	/// <summary>
	///  <inheritdoc cref="MultiLevelPtr" />
	/// </summary>
	/// <param name="pointers">A chain of pointers to resolve</param>
	public MultiLevelPtr(int[] pointers)
	{
		Chain.Base = new IntPtr(pointers[0]);
		Chain.Offsets = ConvertInts(pointers[1..]);
	}

	/// <summary>
	///  <inheritdoc cref="MultiLevelPtr" />
	/// </summary>
	/// <param name="pointers">A chain of pointers to resolve</param>
	public MultiLevelPtr(long[] pointers)
	{
		Chain.Base = new IntPtr(pointers[0]);
		Chain.Offsets = ConvertLongs(pointers[1..]);
	}

	/// <summary>
	///  The chain of pointers to resolve
	/// </summary>
	public PointerChain Chain { get; } = new();

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

	/// <summary>
	///  Structure defining a pointer chain with a base and optional list of offsets.
	/// </summary>
	public class PointerChain
	{
		/// <summary>
		///  Base address of the pointer chain
		/// </summary>
		public IntPtr Base { get; set; }
		/// <summary>
		///  Optional list of offsets containing pointer offsets (from the provided base).
		/// </summary>
		public IList<IntPtr>? Offsets { get; set; }
	}
}