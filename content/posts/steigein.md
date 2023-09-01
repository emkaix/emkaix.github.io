+++
title = "cracking of old driver's license software"
date = "2023-08-27"
author = "mkx"
description = "reverse engineering and license cracking of an old (~2012) driving school software I used to learn with back in the day."
tags = ['reverse-engineering', 'unpacking', 'PE', 'cracking', 'SEH', 'UPX', 'PECompact']
toc = true
+++

## Intro

Recently I came across an old USB drive I purchased from the driving school back in the day when I was obtaining my driver's license. It features educational software which was meant to help you study for the theoretical part of the exam.

[{{< image src="/img/steig_ein/stick.jpg" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/stick.jpg)

Out of curiosity, I wanted to check it out.

[{{< image src="/img/steig_ein/folder.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/folder.png)

The directory structure is nothing special, there is the main executable `steigein.exe` which launches the main program, as well as another executable `InternetUpdater.exe` which can be used to update the software. When I tried to start the main program, a windows popped up, stating:

> The license information on the USB drive is invalid.

[{{< image src="/img/steig_ein/expired.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/expired.png)

Naturally, I was interested in how the license validity check is performed, so I decided to look further into it. However, when I tried to open the binary file in IDA, it showed a message indicating that the executable file was packed.

[{{< image src="/img/steig_ein/ida_packed.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/ida_packed.png)

In order to find out which packer was used, I opened it with [DIE](https://github.com/horsicq/Detect-It-Easy). It recognized the packer as `PECompact`.

[{{< image src="/img/steig_ein/die.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/die.png)

Just for good measure, I also used the default Unix `file` command, which was able to correctly identify it as well.

```bash
» file ./steigein.exe
./steigein.exe: PE32 executable (GUI) Intel 80386, for MS Windows, PECompact2 compressed, 2 sections
```

[PECompact](https://bitsum.com/portfolio/pecompact/) is similar to other packers like UPX, however, in contrast to UPX it has no decompression switch and is closed source. I decided to manually unpack the executable in order to be able to further analyze it in IDA. To do that, I ran the file using [x64dbg](https://github.com/x64dbg/x64dbg).

## PECompact Unpacking

If you run the executable using x64dbg, it generates an `EXCEPTION_ACCESS_VIOLATION` after a few instructions at `0x401016`. However, when you continue execution, it still unpacks and runs the program. Usually this is a sign of using [SEH](https://learn.microsoft.com/en-us/cpp/cpp/structured-exception-handling-c-cpp?view=msvc-170) traps as an anti-debug method. So let's look into what happens here.

[{{< image src="/img/steig_ein/dbg2.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/dbg2.png)

These are the first six instructions before the exception gets thrown:

```asm
00401000 | mov eax,steigein.833A0C
00401005 | push eax
00401006 | push dword ptr fs:[0]
0040100D | mov dword ptr fs:[0],esp
00401014 | xor eax,eax
00401016 | mov dword ptr ds:[eax],ecx
```

Let's deconstruct this by starting with the `fs:[0]` part. For 32-bit Windows, the segment register `FS` points to a structure called `Thread_Information_Block` [(TIB)](https://en.wikipedia.org/wiki/Win32_Thread_Information_Block), which stores information about the currently running thread. It's defined in `winnt.h`:

```cpp
typedef struct _NT_TIB {
    struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
#if defined(_MSC_EXTENSIONS)
    union {
        PVOID FiberData;
        DWORD Version;
    };
#else
    PVOID FiberData;
#endif
    PVOID ArbitraryUserPointer;
    struct _NT_TIB *Self;
} NT_TIB;
```

So `fs:[0]` references the first entry of the TIB, which is a pointer to a `_EXCEPTION_REGISTRATION_RECORD` list (more precisely, the head of the list), which is a linked list of SEH exception handlers. The list entries are also defined inside `winnt.h`:

```cpp
typedef struct _EXCEPTION_REGISTRATION_RECORD {
    struct _EXCEPTION_REGISTRATION_RECORD *Next;
    PEXCEPTION_ROUTINE Handler;
} EXCEPTION_REGISTRATION_RECORD;
```

Which means that each entry consists of two members:

1. A pointer to the next entry
2. A pointer to the exception handler

Once we understand that, it is clear that these instructions register a new SEH handler by building a `_EXCEPTION_REGISTRATION_RECORD` on the stack and prepending it to the linked list.

```asm
00401000 | mov eax,steigein.833A0C      // 0x833A0C is the handler function
00401005 | push eax                     // handler function gets pushed on stack
00401006 | push dword ptr fs:[0]        // push the current first list entry on stack
0040100D | mov dword ptr fs:[0],esp     // set the new entry as head of the list
00401014 | xor eax,eax                  // set eax to 0
00401016 | mov dword ptr ds:[eax],ecx   // throw exception
```

[{{< image src="/img/steig_ein/dbg3.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/dbg3.png)

When a breakpoint is set on the SEH handler address `0x833A0C`, it gets hit immediately after the exception was thrown. Looking at the call stack, you can see that `KiUserExceptionDispatcher` calls `ExecuteHandler`, which in turn calls the handler function `0x833A0C`.

[{{< image src="/img/steig_ein/dbg4.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/dbg4.png)

[{{< image src="/img/steig_ein/dbg5.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/dbg5.png)

The SEH handler itself is pretty straightforward. There is a call to `VirtualAlloc` at `0x833A63` which allocates a chunk of memory with `PAGE_EXECUTE_READWRITE` permissions. After that, a subroutine is  called at `0x833A8D`, that fills this allocated memory region with the necessary instructions to unpack the actual executable. At `0x833AAA`, a call into this memory region takes place which subsequently unpacks the executable data. I didn't bother to look at the unpacking in-depth, but there are some calls to `zlib` which indicates that PECompact makes use of the `Deflate` compression algorithm.

[{{< image src="/img/steig_ein/dbg6.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/dbg6.png)

At `0x833ACE`, there is a `jmp eax` instruction which transfers control to the now unpacked executable. The address of the OEP can be found by simply reading the value of `eax`, which in this case is `0x50BB51`.

After unpacking, the original `Import Directory` is not available as it is the unpacking code that resolves the imports. The Scylla plugin of x64dbg can find the populated IAT and reconstruct the original `Import Directory`, given the OEP which we now know. The resulting PE file can then be dumped on disk.

[{{< image src="/img/steig_ein/dbg7.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/dbg7.png)

## Analyzation in IDA

With the unpacked executable at hand, we can now further analyze it in IDA. First I was looking for the "invalid license information" string that is shown in the message box, in order to locate the license check. However, IDA had problems defining some of the strings due to different string encodings being used. I had to manually go through a chunk of undefined strings and manually define them using the `Windows-1252` encoding. The "invalid license information" string is cross referenced in only one location which can be seen on the screenshot.

[{{< image src="/img/steig_ein/ida1.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/ida1.png)

This function is called early on when the program is started and seems to perform various checks in order for the application to run. For example, in line 63 of the decompilation view, the function `sub_407C00` checks the version of the OS to be at least Windows XP, in line 69 `sub_41E560` performs some registry checks for the `StorageModule` library, which I assume is used for generating the learning reports which you can print out. Every one of these checks is an `if` block, and if the check fails, [`PostQuitMessage(0)`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postquitmessage) is called followed by an `exit(0)`. Line 79 is the license check (`sub_4BD9D0`), which can be derived by the "invalid license" error message that gets passed inside the if block (which gets executed when the check fails).

Somewhere in the license check subroutine there are several [`WMI`](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page) query strings referenced. These queries check if the program is run on a valid USB drive.

[{{< image src="/img/steig_ein/ida2.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/ida2.png)



```powershell
❯ Get-WmiObject -Query "SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'"

Partitions : 1
DeviceID   : \\.\PHYSICALDRIVE6
Model      : HE STEIG EIN! USB USB Device
Size       : 1990517760
Caption    : HE STEIG EIN! USB USB Device
```

```powershell
❯ Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='\\.\PHYSICALDRIVE6'} WHERE AssocClass = Win32_DiskDriveToDiskPartition"

NumberOfBlocks   : 3890584
BootPartition    : True
Name             : Datenträgernr. 6, Partitionsnr. 0
PrimaryPartition : True
Size             : 1991979008
Index            : 0
```

There are also routines for checking the current time and comparing it to the stored validity date.

[{{< image src="/img/steig_ein/ida3.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/ida3.png)

The WMI queries and the date check are both called by the outermost `sub_4BD9D0`, so every check up to this point can be skipped by simply changing the condition of the `if` statement, in this case the `jnz` instruction is patched to `jz`.

[{{< image src="/img/steig_ein/ida4.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/ida4.png)

With this patch, the application still crashes on startup. However, the cause is quickly identified - at some point, the application assumes the existence of some registry keys, which are not present.

[{{< image src="/img/steig_ein/ida5.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/ida5.png)

I thought it would be the easiest to use `ProcessMonitor` from the Sysinternals software package to monitor the registry accesses.

[{{< image src="/img/steig_ein/pm1.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/pm1.png)

You can see that the application tries to access the key `HKEY_CURRENT_USER\Software\Ebner\Steig ein! 10.0`. I created the key and ran the program again.

[{{< image src="/img/steig_ein/pm2.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/pm2.png)

The application tries to access these three values: `ResSettingTransferRequired`, `ResUpdateDone` and `UpdateDatacontainerVersion`. After I created the entries, the application starts and can be used normally.

[{{< image src="/img/steig_ein/app1.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/app1.png)

[{{< image src="/img/steig_ein/app3.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/app3.png)

[{{< image src="/img/steig_ein/app2.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/app2.png)

## Bonus: UPX

As a bonus, I also wanted to check out the `InternetUpdater.exe`. It says that it's packed with UPX:

[{{< image src="/img/steig_ein/die2.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/die2.png)

However, when I wanted to unpack it, the following error occured:

```powershell
❯ upx -d .\InternetUpdater.exe
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2023
UPX 4.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Aug 8th 2023

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
upx: .\InternetUpdater.exe: CantUnpackException: file is modified/hacked/protected; take care!!!

Unpacked 0 files.
```

Apparently, it has been modified in order to make it harder to unpack. But it was quite easy to figure out what they did. It's a common trick that UPX packed malware also uses - deleting sections of the file so that UPX doesn't recognize it as a packed binary. For example, here is an arbitrary file that was packed with UPX:

[{{< image src="/img/steig_ein/hex1.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/hex1.png)

As you can see, there are three string references, `UPX1`, `UPX2` and `UPX!`. Now for comparison the modified `InternetUpdater.exe`:

[{{< image src="/img/steig_ein/hex2.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/hex2.png)

You can see that they simply deleted the `UPX` prefix. After filling it back in, it can be unpacked.

```powershell
❯ upx -d .\InternetUpdater.exe
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2023
UPX 4.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Aug 8th 2023

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   1168768 <-    461696   39.50%    win32/pe     InternetUpdater.exe

Unpacked 1 file.
```

The application itself isn't really interesting, the servers for updating the software are offline, probably for a long time. However, there is a file in the directory called `InternetUpdater.dat`, which appears to be a ZIP file.

```bash
» file ./InternetUpdater.dat
./InternetUpdater.dat: Zip archive data, at least v2.0 to extract, compression method=deflate
```

When I tried to unzip it, I realised it was protected with a password.

[{{< image src="/img/steig_ein/zip1.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/zip1.png)

I figured that `InternetUpdater.exe` extracts this archive at some point, so the password must be stored in the binary file. I searched for various string references, in order to find it. In the 7-Zip window, you can see the name of the file `_TUProj.dat`, and when you search for this string reference, a suspicious value is stored in its vicinity.

[{{< image src="/img/steig_ein/zip2.png" position="center" style="border-radius: 8px;" >}}](/img/steig_ein/zip2.png)

I just guessed that this was the password, and it was. I then opened `_TUProj.dat`, which appears to be a project file containing LUA code for the software [True Update](https://www.indigorose.com/trueupdate/).

```lua
        ÿÿ  CIREvent    
Client Scriptÿš------------------------------------------
-- Download and run the Server Script
------------------------------------------

-- Suppress all screens until an update is available?
g_SilentUntilUpdateAvailable = false;

-- Download and run the Server Script silently or using screens
if(g_SilentUntilUpdateAvailable) then

	-- Get the list of TrueUpdate Servers
	tableTrueUpdateServers = TrueUpdate.GetUpdateServerList();

	if(tableTrueUpdateServers) then

		-- Loop through the list of TrueUpdate Servers
		for index, ServerName in tableTrueUpdateServers do

			-- Attempt to download the server configuration files
			GotServerFiles = TrueUpdate.GetServerFile(ServerName, false);
	
			-- If the download was successful, run the server script
			if(GotServerFiles) then
				TrueUpdate.RunScript("Server Script");
				break;
			end
		end
	end
	
else

(...)

**********************************************************************************
Function:	g_OnRegisterFileFailed
Purpose:	Called from the update when a file fails COM or TypeLib registration.
Arguments:	(number) nRegType - The type of registration. 0 = COM (DllRegisterServer), 1 = TypeLib
          	(string) strFilename - The full path and filename of the file that failed registration.
          	(string) strErrorMsg - The translated error message.
          	(number) nErrorCode - The error code.
Returns:	(boolean) true if the update should continue or false to abort
**********************************************************************************
--]]
function g_OnRegisterFileFailed(nRegType, strFilename, strErrorMsg, nErrorCode)
	local strMessage = "";
	
	if(nRegType == 0)then
		strMessage = TrueUpdate.GetLocalizedString("ERR_REGISTER_COM");
	else
		strMessage = TrueUpdate.GetLocalizedString("ERR_REGISTER_TLB");
	end
	
	strMessage = strMessage.." "..strFilename.."\r\n"..strErrorMsg.." ("..nErrorCode..")";
	
	if(not _SilentInstall)then
		Dialog.Message(TrueUpdate.GetLocalizedString("MSG_NOTICE"),strMessage,MB_OK,MB_ICONEXCLAMATION);
	end

	-- Continue with the update.  Change to false to abort the update.
	return true;
end

(...)
```

I couldn't find anything interesting here, but this was a bonus after all.