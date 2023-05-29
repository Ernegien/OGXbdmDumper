using Serilog;
using Serilog.Core;
using Serilog.Events;
using ShellProgressBar;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Reflection;
using DustInTheWind.ConsoleTools.Controls.Menus;
using DustInTheWind.ConsoleTools.Controls.InputControls;

namespace OGXbdmDumper
{
    internal class Program
    {
        /// <summary>
        /// Allows the switching of log event levels without creating a new logger.
        /// </summary>
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static readonly LoggingLevelSwitch _levelSwitch = new(LogEventLevel.Information);

        /// <summary>
        /// The minimum level used to filter message output.
        /// </summary>
        public static LogEventLevel LogLevel
        {
            get { return _levelSwitch.MinimumLevel; }
            set
            {
                if (value == _levelSwitch.MinimumLevel) return;

                _levelSwitch.MinimumLevel = value;
                Log.Information("File logger level changed to {LogEventLevel}", value);
            }
        }

        static void Main(string[] args)
        {
            try
            {
                InitializeLogging();

                // obtain a connection
                using var xbox = GetXboxConnection();

                // create dated folder underneath selection to help prevent accidental overwrites
                var path = Path.Combine(GetOutputDirectory(), DateTime.Now.ToString("yyyyMMddHHmmss"));
                Directory.CreateDirectory(path);

                // pause execution to prevent any interference
                xbox.Stop();

                // dump all the things
                DumpXbdmMemory(xbox, Path.Combine(path, "xbdm.dll.memory"));
                DumpKernelMemory(xbox, Path.Combine(path, "xboxkrnl.exe.memory"));
                DumpBiosImage(xbox, Path.Combine(path, "bios.bin"));
                ValidateRpc(xbox);
                DumpEeprom(xbox, Path.Combine(path, "eeprom.bin"));
                DumpHddImage(xbox, Path.Combine(path, "hdd.img"));
                DumpHddFiles(xbox, Path.Combine(path, "hdd"));

                // resume execution
                xbox.Go();
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Fatal error encountered!");
            }
            finally
            {
                // cleanup
                Log.CloseAndFlush();
            }
        }

        public static void InitializeLogging()
        {
            // initialize logger
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.ControlledBy(_levelSwitch)
                .WriteTo.Console(restrictedToMinimumLevel: LogEventLevel.Information)
                .WriteTo.File("log.txt", buffered: true, flushToDiskInterval: TimeSpan.FromSeconds(1))
                .CreateLogger();

            // log application information
            Log.Information("https://github.com/Ernegien/OGXbdmDumper");
            Log.Information("Version {0}", Assembly.GetExecutingAssembly().GetName().Version);

            // provide the option for additional log capture
            LogLevel = YesNo("Enable verbose file logging?", false) ? LogEventLevel.Verbose : LogEventLevel.Information;
        }

        public static Xbox GetXboxConnection()
        {
            var xbox = new Xbox();

            // attempt xbox auto-discovery
            var xboxen = xbox.Discover();

            if (xboxen.Count > 0)
            {
                var textMenu = new TextMenu
                {
                    TitleText = "The following Xboxes were discovered on the local network:",
                    QuestionText = "Connect to: "
                };
                for (int i = 0; i < xboxen.Count; i++)
                {
                    textMenu.AddItem(new TextMenuItem()
                    {
                        Id = i.ToString(),
                        Text = xboxen[i].Endpoint.Address.ToString() +
                            (string.IsNullOrWhiteSpace(xboxen[i].Name) ? string.Empty : " (" + xboxen[i].Name + ")")
                    });
                }
                textMenu.AddItem(new TextMenuItem()
                {
                    Id = xboxen.Count.ToString(),
                    Text = "Other"
                });

                textMenu.Display();

                if (textMenu.SelectedIndex < xboxen.Count)
                {
                    xbox.Connect(xboxen[textMenu.SelectedIndex.Value].Endpoint);
                    return xbox;
                }
            }
            else Log.Warning("Auto-discovery failed! Manually enter connection information instead.");

            // manual address entry
            // TODO: custom parser for ip address
            string ip = ValueControl<string>.QuickRead("IP Address:");
            var port = new ValueControl<ushort>("Alternate Port [leave blank if no]:")
            {
                AcceptDefaultValue = true,
                DefaultValue = 731
            }.Read();

            xbox.Connect(new IPEndPoint(IPAddress.Parse(ip), port));
            return xbox;
        }

        public static string GetOutputDirectory()
        {
            // TODO: custom parser for path validation
            var path = ValueControl<string>.QuickRead("Enter output directory path:");

            if (!Directory.Exists(path))
                throw new DirectoryNotFoundException(path);

            Log.Information("Using {0} as the output directory path.", path);
            return path;
        }

        public static void DumpXbdmMemory(Xbox xbox, string path)
        {
            if (!YesNo("Dump xbdm.dll from memory?"))
                return;

            Log.Information("Dumping xbdm.dll from memory.");

            var xbdm = xbox.Modules.Find(m => m.Name == "xbdm.dll");
            if (xbdm != null)
            {
                File.WriteAllBytes(path, xbox.Memory.ReadBytes(xbdm.BaseAddress, xbdm.Size));
            }
        }

        public static void DumpKernelMemory(Xbox xbox, string path)
        {
            if (!YesNo("Dump xboxkrnl.exe from memory?"))
                return;

            Log.Information("Dumping xboxkrnl.exe from memory.");

            var kernel = xbox.Modules.Find(m => m.Name == "xboxkrnl.exe");
            if (kernel != null)
            {
                byte[] page = new byte[0x1000];
                using var fs = File.Create(path);
                using var bw = new BinaryWriter(fs);

                // loop through each page in the kernel address range skipping any invalid ones since the init section will be deallocated               
                for (long position = kernel.BaseAddress; position < kernel.BaseAddress + kernel.Size; position += page.Length)
                {
                    bw.Write(xbox.IsValidAddress(position) ? xbox.Memory.ReadBytes(position, page.Length) : page);
                }                
            }
        }

        public static void ValidateRpc(Xbox xbox)
        {
            Log.Information("Validating remote procedure call functionality.");

            // mov eax, 0DEADBEEFh
            // ret
            xbox.WriteMemory(xbox.ScratchBuffer.Address, new byte[] { 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xC3 });
            if (xbox.Call(xbox.ScratchBuffer.Address) != 0xDEADBEEF)
            {
                Log.Warning("Remote procedure call failure!");
                throw new InvalidDataException();
            }
        }

        public static void DumpEeprom(Xbox xbox, string path)
        {
            if (!YesNo("Dump EEPROM?"))
                return;

            Log.Information("Dumping EEPROM.");

            // configure progress bar
            const int eepromSize = 256;
            using var progress = CreatePercentProgressBar();

            // read a byte at a time
            using var fs = File.Create(path);
            using var bw = new BinaryWriter(fs);
            for (int i = 0; i < eepromSize; i++)
            {
                xbox.Kernel.HalReadSMBusValue(0xA8, i, false, xbox.ScratchBuffer.Address);
                bw.Write(xbox.Memory.ReadByte(xbox.ScratchBuffer.Address));
                progress.AsProgress<float>().Report((float)i / eepromSize);
            }
            progress.AsProgress<float>().Report(1.0f);
        }

        public static void DumpBiosImage(Xbox xbox, string path)
        {
            if (!YesNo("Dump BIOS?"))
                return;

            Log.Information("Dumping BIOS image from flash.");

            // take the first 1MB which is enough for all legit development gear
            byte[] bios = new byte[1024 * 1024];

            // configure progress bar
            var chunkSize = 0x1000;
            var chunks = bios.Length / chunkSize;
            using var progress = CreatePercentProgressBar();

            // read 4kb at a time
            for (int i = 0; i < chunks; i++)
            {
                xbox.ReadMemory(0xFF000000 + i * chunkSize, bios, i * chunkSize, chunkSize);
                progress.AsProgress<float>().Report((float)i / chunks);
            }
            progress.AsProgress<float>().Report(1.0f);

            // find smallest 256KB-aligned unique chunk since it gets mirrored throughout the upper 16MB range
            byte[] testPattern = bios.Take(1024 * 256).ToArray();
            int flashSize = bios.IndexOfArray(testPattern, (int)testPattern.Length);
            if (flashSize == -1)
                flashSize = bios.Length;

            File.WriteAllBytes(path, bios.Take(flashSize).ToArray());
        }

        public static void DumpHddImage(Xbox xbox, string path)
        {
            if (!YesNo("Dump HDD image?"))
                return;

            // expand scratch buffer and switch to unsafe mode for increased performance
            xbox.ExpandScratchBuffer();
            xbox.SafeMode = false;

            Log.Information("Dumping HDD image.");

            // remote memory map
            //FileHandle:
            //    dd    0
            //IoStatusBlock: +4
            //    dd	0
            //    dd	0
            //ObjectAttributes:	+12	; (OBJECT ATTRIBUTES)
            //    dd	0		    ; HANDLE RootDirectory
            //    dd	ObjectName	; PANSI_STRING ObjectName
            //    dd	00000040h	; ULONG Attributes = FILE_ATTRIBUTE_DEVICE
            //ObjectName:	 +24	; (PANSI_STRING)
            //    dw	26;		    ; USHORT Length
            //    dw	26;		    ; USHORT MaximumLength
            //    dd	FileName	; PCHAR Buffer
            // FileName: + 32
            // db	"\Device\Harddisk0\Partition0", 0
            uint scratch = xbox.ScratchBuffer.Address;
            uint scratchSize = xbox.ScratchBuffer.Size;
            uint fileHandleAddr = scratch;
            uint iOStatusBlockAddr = scratch + 4;
            uint objectAttributesAddr = scratch + 12;
            uint objectNameAddr = scratch + 24;
            uint fileNameAddr = scratch + 32;

            // initialize remote memory
            string name = @"\Device\Harddisk0\Partition0";      // physical disk path
            xbox.Memory.Position = scratch;
            xbox.Memory.Write((uint)0);
            xbox.Memory.Write((uint)0);
            xbox.Memory.Write((uint)0);
            xbox.Memory.Write((uint)0);
            xbox.Memory.Write(objectNameAddr);
            xbox.Memory.Write((uint)0x40);
            xbox.Memory.Write((ushort)name.Length);
            xbox.Memory.Write((ushort)name.Length);
            xbox.Memory.Write(fileNameAddr);
            xbox.Memory.WriteAscii(name);
            xbox.Memory.Write(0);

            // obtain a handle to the raw physical hdd device
            var status = xbox.Call(xbox.Kernel.Exports.NtOpenFile,
                    fileHandleAddr,         // PHANDLE FileHandle
                    0xC0000000,             // ACCESS_MASK DesiredAccess = GENERIC_WRITE | GENERIC_READ
                    objectAttributesAddr,   // POBJECT_ATTRIBUTES ObjectAttributes
                    iOStatusBlockAddr,      // PIO_STATUS_BLOCK IoStatusBlock
                    (uint)3,                // ULONG ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE
                    (uint)0x60              // ULONG OpenOptions = FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
                );
            if (status != 0)
                throw new Win32Exception((int)status);
            uint handle = xbox.Memory.ReadUInt32(fileHandleAddr);

            // memory map
            var geometryInfoAddr = scratch + 100;
            var geometryInfoSize = 24;

            // get the disk geometry information
            status = xbox.Call(xbox.Kernel.Exports.NtDeviceIoControlFile,
                    handle,                                 // HANDLE FileHandle
                    0,                                      // HANDLE Event
                    0,                                      // PIO_APC_ROUTINE ApcRoutine
                    0,                                      // PVOID ApcContext
                    iOStatusBlockAddr,                      // PIO_STATUS_BLOCK IoStatusBlock
                    (7 << 16) | (0 << 14) | (0 << 2) | 0,   // ULONG IoControlCode = IOCTL_DISK_BASE << 16 | FILE_ANY_ACCESS << 14 | Function << 2 | METHOD_BUFFERED
                    0,                                      // PVOID InputBuffer
                    0,                                      // ULONG InputBufferLength
                    geometryInfoAddr,                       // PVOID OutputBuffer
                    geometryInfoSize                        // ULONG OutputBufferLength
                );
            if (status != 0)
                throw new Win32Exception((int)status);

            // calculate the total raw disk size
            long cylinders = xbox.Memory.ReadInt64(geometryInfoAddr);
            int tracksPerCylinder = xbox.Memory.ReadInt32(geometryInfoAddr + 12);
            int sectorsPerTrack = xbox.Memory.ReadInt32(geometryInfoAddr + 16);
            long bytesPerSector = xbox.Memory.ReadInt32(geometryInfoAddr + 20);
            long size = cylinders * tracksPerCylinder * sectorsPerTrack * bytesPerSector;
            Log.Information("Detected {0} GB HDD ({1} bytes).", (int)((float)size / (1024 * 1024 * 1024)), size.ToHexString());

            // get the required 4KB-aligned/sized buffer within scratch space
            uint bufferAddress = scratch + 16; // first 16 bytes of scratch is reserved for NtReadFile args
            bufferAddress = (bufferAddress + 0xFFF) & 0xFFFFF000; // align up to the next 4KB
            uint bufferSize = scratch + scratchSize - bufferAddress;
            bufferSize &= 0xFFFFF000; // align down to the next 4KB
            byte[] buffer = new byte[bufferSize];

            // make sure we haven't gone too far
            if (bufferSize == 0)
                throw new OutOfMemoryException("Not enough aligned scratch space!");

            using var progress = CreatePercentProgressBar();
            using var fs = File.Create(path);
            using var bw = new BinaryWriter(fs);

            long diskOffset = 0;
            while (diskOffset < size)
            {
                uint bytesToRead = (uint)Math.Min((ulong)bufferSize, (ulong)(size - diskOffset));

                Log.Verbose("Reading {0} bytes from disk offset {1}", bytesToRead, diskOffset);

                try
                {
                    xbox.Memory.Write(scratch, diskOffset);
                    xbox.Kernel.NtReadFile(
                        handle,         // HANDLE FileHandle
                        0,              // HANDLE Event
                        0,              // PIO_APC_ROUTINE ApcRoutine
                        0,              // PVOID ApcContext
                        scratch + 8,    // PIO_STATUS_BLOCK IoStatusBlock
                        bufferAddress,  // PVOID Buffer
                        bytesToRead,    // ULONG Length
                        scratch         // PLARGE_INTEGER ByteOffset
                    );

                    xbox.ReadMemory(bufferAddress, buffer, 0, (int)bytesToRead);
                }
                catch (Exception ex)
                {
                    Log.Warning(ex, "Read failure at {0}", diskOffset.ToHexString());
                    buffer = new byte[bytesToRead];
                }
                finally
                {
                    bw.Write(buffer);
                    fs.Flush();
                    diskOffset += bytesToRead;
                }

                progress.AsProgress<float>().Report((float)diskOffset / size);
            }
            progress.AsProgress<float>().Report(1.0f);

            // cleanup
            xbox.Kernel.NtClose(handle);
        }

        private static void DumpDirectory(Xbox xbox, string remotePath, string localPath)
        {
            Log.Information("Downloading {0}", remotePath);
            Directory.CreateDirectory(localPath);

            try
            {
                var list = xbox.GetDirectoryList(remotePath);

                foreach (var item in list)
                {
                    if (item.Attributes.HasFlag(FileAttributes.Directory))
                    {
                        DumpDirectory(xbox, item.FullName, Path.Combine(localPath, item.Name));
                    }
                    else
                    {
                        try
                        {
                            Log.Information("Downloading file {0}", item.Name);
                            xbox.GetFile(Path.Combine(localPath, item.Name), item.FullName);
                        }
                        catch (Exception ex)
                        {
                            Log.Warning(ex, item.Name);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Warning(ex, remotePath);
            }
        }

        public static void DumpHddFiles(Xbox xbox, string path)
        {
            if (!YesNo("Dump files from HDD?"))
                return;

            Log.Information("Dumping files from hdd.");

            foreach (var drive in xbox.GetDrives())
            {
                DumpDirectory(xbox, drive.ToString() + ":\\", Path.Combine(path, drive.ToString()));
            }
        }

        private static ProgressBar CreatePercentProgressBar()
        {
            return new ProgressBar(10000, "Completed",
                new ProgressBarOptions
                {
                    ForegroundColor = ConsoleColor.Yellow,
                    ForegroundColorDone = ConsoleColor.DarkGreen,
                    BackgroundColor = ConsoleColor.DarkGray,
                    BackgroundCharacter = '\u2593'
                });
        }

        private static bool YesNo(string question, bool defaultYes = true)
        {
            var yesNoQuestion = new YesNoQuestion(question)
            {
                DefaultAnswer = defaultYes ? YesNoAnswer.Yes : YesNoAnswer.No
            };

            return yesNoQuestion.ReadAnswer() == YesNoAnswer.Yes;
        }
    }
}