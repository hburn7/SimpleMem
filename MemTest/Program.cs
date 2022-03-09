using SimpleMem;

var mem = new MemoryChain32("FTLGame");
var proc = mem.Process;
Console.WriteLine($"Process main module: {proc.MainModule.BaseAddress.ToInt32():X} " +
                  $"| SimpleMem: {mem.Module.BaseAddress.ToInt32():X}");

var aob = "A9 02 A5 02 A1 02 9D 02 99 02 94 02 90 02 8C 02 87 02 82 02 7E 02 7B 02 77 02 74 02 70 02 6D 02 69 02 66 02 62 02 5F 02 5C 02 58 02 55 02 57 02 59 02 5B 02 5C 02 5E 02 5F 02 61 02 63 02 64 02 66 02 67 02 69 02 6B 02 6C 02 6E 02 70 02 78 02 81 02 8A 02 93";
var result = mem.AoBScan(aob);
foreach (var address in result)
{
	Console.WriteLine(address.ToString("X"));
}
