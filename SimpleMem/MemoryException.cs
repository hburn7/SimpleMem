using System.Runtime.Serialization;

namespace SimpleMem;

public static class ErrorCodes
{
	/// <summary>
	///  Lookup dictionary for relevant error codes and their meanings.
	/// </summary>
	public static readonly Dictionary<uint, string> CodeLookup = new()
	{
		{ 5, "Access is denied" },
		{ 6, "The handle is invalid" },
		{ 8, "Not enough memory resources are available to process this command" },
		{ 11, "An attempt was made to load a program with an incorrect format" },
		{ 12, "The access code is invalid" },
		{ 13, "The data is invalid" },
		{ 14, "Not enough memory is available to complete this operation" },
		{ 87, "Invalid parameter" },
		{ 299, "Only part of a ReadProcessMemory or WriteProcessMemory request was completed" },
		{ 487, "Attempt to access invalid address" },
		{ 998, "Invalid access to memory location" }
	};
}

/// <summary>
///  Thrown when memory read operations have failed.
///  Intended to be used as a support tool for hard-to-debug issues.
/// </summary>
public class MemoryReadException : Exception
{
	/// <inheritdoc />
	public MemoryReadException() {}

	/// <inheritdoc />
	protected MemoryReadException(SerializationInfo info, StreamingContext context) : base(info, context) {}

	/// <inheritdoc />
	public MemoryReadException(string? message) : base(message) {}

	/// <inheritdoc />
	public MemoryReadException(uint error) :
		base($"Error code {error} {ErrorCodes.CodeLookup.GetValueOrDefault(error)}") {}

	/// <inheritdoc />
	public MemoryReadException(string? message, Exception? innerException) : base(message, innerException) {}
}

/// <summary>
///  Thrown when memory write operations have failed.
///  Intended to be used as a support tool for hard-to-debug issues.
/// </summary>
public class MemoryWriteException : Exception
{
	/// <inheritdoc />
	public MemoryWriteException() {}

	/// <inheritdoc />
	protected MemoryWriteException(SerializationInfo info, StreamingContext context) : base(info, context) {}

	/// <inheritdoc />
	public MemoryWriteException(string? message) : base(message) {}

	/// <inheritdoc />
	public MemoryWriteException(uint error) :
		base($"Error code {error} {ErrorCodes.CodeLookup.GetValueOrDefault(error)}") {}

	/// <inheritdoc />
	public MemoryWriteException(string? message, Exception? innerException) : base(message, innerException) {}
}