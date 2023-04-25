using System.Text;
using System.Net;
using Microsoft.Extensions.Caching.Memory;
using Serilog;
using Serilog.Events;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace OGXbdmDumper
{
    public class Xbox : IDisposable
    {
        #region Properties

        private bool _disposed;

        private const int _cacheDuration = 1;   // in minutes

        private readonly MemoryCache _cache = new MemoryCache(new MemoryCacheOptions { ExpirationScanFrequency = TimeSpan.FromMinutes(_cacheDuration) });

        private bool? _hasFastGetmem;

        private bool _hasScratchReassigned;

        public bool HasFastGetmem
        {
            get
            {
                if (_hasFastGetmem == null)
                {
                    try
                    {
                        long testAddress = 0x10000;
                        if (IsValidAddress(testAddress))
                        {
                            Session.SendCommandStrict("getmem2 addr={0} length=1", testAddress.ToHexString());
                            Session.ClearReceiveBuffer();
                            _hasFastGetmem = true;
                            Log.Information("Fast getmem support detected.");
                        }                      
                        else _hasFastGetmem = false;
                    }
                    catch
                    {
                        _hasFastGetmem = false;
                    }
                }
                return _hasFastGetmem.Value;
            }
        }

        /// <summary>
        /// Determines whether precautions (usually at the expense of performance) should be taken to prevent crashing the xbox.
        /// </summary>
        public bool SafeMode { get; set; } = true;

        public bool IsConnected => Session.IsConnected;

        public int SendTimeout { get => Session.SendTimeout; set => Session.SendTimeout = value; }

        public int ReceiveTimeout { get => Session.ReceiveTimeout; set => Session.ReceiveTimeout = value; }

        public Connection Session { get; private set; } = new Connection();

        public ConnectionInfo? ConnectionInfo { get; protected set; }

        /// <summary>
        /// The Xbox memory stream.
        /// </summary>
        public XboxMemoryStream Memory { get; private set; }

        public Kernel Kernel { get; private set; }

        public List<Module> Modules => GetModules();

        public List<Thread> Threads => GetThreads();

        public Version Version => GetVersion();

        public MemoryRegion ScratchBuffer { get; private set; }

        #endregion

        #region Connection

        public void Connect(string host, int port = 731)
        {
            _cache.Clear();
            ConnectionInfo = Session.Connect(host, port);

            // init subsystems
            Memory = new XboxMemoryStream(this);
            Kernel = new Kernel(this);

            Log.Information("Loaded Modules:");
            foreach (var module in Modules)
            {
                Log.Information("\t{0} ({1})", module.Name, module.TimeStamp);
            }

            Log.Information("Xbdm Version {0}", Version);
            Log.Information("Kernel Version {0}", Kernel.Version);

            // enable remote code execution and use the remainder reloc section as scratch
            ScratchBuffer = PatchXbdm(this);
            Log.Information("Using {0} bytes of scratch space at address {1}.",
                ScratchBuffer.Size.ToHexString(), ScratchBuffer.Address.ToHexString());
        }

        public void Disconnect()
        {
            Session.Disconnect();
            ConnectionInfo = null;
            _cache.Clear();
        }

        public List<ConnectionInfo> Discover(int timeout = 500)
        {
            return ConnectionInfo.DiscoverXbdm(731, timeout);
        }

        public void Connect(IPEndPoint endpoint)
        {
            Connect(endpoint.Address.ToString(), endpoint.Port);
        }

        public void Connect(int timeout = 500)
        {
            Connect(Discover(timeout).First().Endpoint);
        }

        #endregion

        #region Memory

        public bool IsValidAddress(long address)
        {
            try
            {
                Session.SendCommandStrict("getmem addr={0} length=1", address.ToHexString());
                return "??" != Session.ReceiveMultilineResponse()[0];
            }
            catch
            {
                return false;
            }
        }

        public void ReadMemory(long address, Span<byte> buffer)
        {
            if (HasFastGetmem && !SafeMode)
            {
                Session.SendCommandStrict("getmem2 addr={0} length={1}", address.ToHexString(), buffer.Length);
                Session.Read(buffer);
                if (Log.IsEnabled(LogEventLevel.Verbose))
                {
                    Log.Verbose(buffer.ToHexString());
                }
            }
            else
            {
                Session.SendCommandStrict("getmem addr={0} length={1}", address.ToHexString(), buffer.Length);

                int bytesRead = 0;
                string hexString;
                while ((hexString = Session.ReceiveLine()) != ".")
                {
                    Span<byte> slice = buffer.Slice(bytesRead, hexString.Length / 2);
                    slice.FromHexString(hexString);
                    bytesRead += slice.Length;
                }
            }
        }

        public void ReadMemory(long address, byte[] buffer, int offset, int count)
        {
            ReadMemory(address, buffer.AsSpan(offset, count));
        }

        public void ReadMemory(long address, int count, Stream destination)
        {
            // argument checks
            if (address < 0) throw new ArgumentOutOfRangeException(nameof(address));
            if (count <= 0) throw new ArgumentOutOfRangeException(nameof(count));
            if (destination == null) throw new ArgumentNullException(nameof(destination));

            Span<byte> buffer = stackalloc byte[1024 * 80];

            while (count > 0)
            {
                int bytesToRead = Math.Min(buffer.Length, count);

                Span<byte> slice = buffer.Slice(0, bytesToRead);
                ReadMemory(address, slice);
                destination.Write(slice);

                count -= bytesToRead;
                address += (uint)bytesToRead;
            }
        }

        public void WriteMemory(long address, ReadOnlySpan<byte> buffer)
        {
            const int maxBytesPerLine = 240;
            int totalWritten = 0;

            while (totalWritten < buffer.Length)
            {
                ReadOnlySpan<byte> slice = buffer.Slice(totalWritten, Math.Min(maxBytesPerLine, buffer.Length - totalWritten));
                Session.SendCommandStrict("setmem addr={0} data={1}", (address + totalWritten).ToHexString(), slice.ToHexString());
                totalWritten += slice.Length;
            }
        }

        public void WriteMemory(long address, byte[] buffer, int offset, int count)
        {
            WriteMemory(address, buffer.AsSpan(offset, count));
        }

        public void WriteMemory(long address, int count, Stream source)
        {
            // argument checks
            if (address < 0) throw new ArgumentOutOfRangeException(nameof(address));
            if (count <= 0) throw new ArgumentOutOfRangeException(nameof(count));
            if (source == null) throw new ArgumentNullException(nameof(source));

            Span<byte> buffer = stackalloc byte[1024 * 80];

            while (count > 0)
            {
                int bytesRead = source.Read(buffer.Slice(0, Math.Min(buffer.Length, count)));
                WriteMemory(address, buffer.Slice(0, bytesRead));

                count -= bytesRead;
                address += bytesRead;
            }
        }

        #endregion

        #region Process

        public List<Thread> GetThreads()
        {
            List<Thread> threads = new List<Thread>();

            Session.SendCommandStrict("threads");
            foreach (var threadId in Session.ReceiveMultilineResponse())
            {
                Session.SendCommandStrict("threadinfo thread={0}", threadId);
                var info = Connection.ParseKvpResponse(string.Join(Environment.NewLine, Session.ReceiveMultilineResponse()));

                threads.Add(new Thread
                {
                    Id = Convert.ToInt32(threadId),
                    Suspend = (int)(uint)info["suspend"], // initially -1 in earlier xbdm versions, 0 in later ones
                    Priority = (int)(uint)info["priority"],
                    TlsBase = (uint)info["tlsbase"],

                    // optional depending on xbdm version
                    Start = info.ContainsKey("start") ? (uint)info["start"] : 0,
                    Base = info.ContainsKey("base") ? (uint)info["base"] : 0,
                    Limit = info.ContainsKey("limit") ? (uint)info["limit"] : 0,
                    CreationTime = DateTime.FromFileTime(
                        (info.ContainsKey("createhi") ? (((long)(uint)info["createhi"]) << 32) : 0) |
                        (info.ContainsKey("createlo") ? (uint)info["createlo"] : 0))
                });
            }

            return threads;
        }

        public List<Module> GetModules()
        {
            List<Module> modules = new List<Module>();

            Session.SendCommandStrict("modules");
            foreach (var moduleResponse in Session.ReceiveMultilineResponse())
            {
                var moduleInfo = Connection.ParseKvpResponse(moduleResponse);
                Module module = new Module
                {
                    Name = (string)moduleInfo["name"],
                    BaseAddress = (uint)moduleInfo["base"],
                    Size = (int)(uint)moduleInfo["size"],
                    Checksum = (uint)moduleInfo["check"],
                    TimeStamp = DateTimeOffset.FromUnixTimeSeconds((uint)moduleInfo["timestamp"]).DateTime,
                    Sections = new List<ModuleSection>(),
                    HasTls = moduleInfo.ContainsKey("tls"),
                    IsXbe = moduleInfo.ContainsKey("xbe")
                };

                Session.SendCommandStrict("modsections name=\"{0}\"", module.Name);
                foreach (var sectionResponse in Session.ReceiveMultilineResponse())
                {
                    var sectionInfo = Connection.ParseKvpResponse(sectionResponse);
                    module.Sections.Add(new ModuleSection
                    {
                        Name = (string)sectionInfo["name"],
                        Base = (uint)sectionInfo["base"],
                        Size = (int)(uint)sectionInfo["size"],
                        Flags = (uint)sectionInfo["flags"]
                    });
                }

                modules.Add(module);
            }

            return modules;
        }

        public Version GetVersion()
        {
            var version = _cache.Get<Version>(nameof(GetVersion));
            if (version == null)
            {
                try
                {
                    // peek inside VS_VERSIONINFO struct
                    var versionAddress = GetModules().FirstOrDefault(m => m.Name.Equals("xbdm.dll")).GetSection(".rsrc").Base + 0x98;

                    // call getmem directly to avoid dependency loops with ReadMemory checking the version
                    Span<byte> buffer = stackalloc byte[sizeof(ushort) * 4];
                    Session.SendCommandStrict("getmem addr={0} length={1}", versionAddress.ToHexString(), buffer.Length);
                    buffer.FromHexString(Session.ReceiveMultilineResponse().First());

                    version = new Version(
                        BitConverter.ToUInt16(buffer.Slice(2, sizeof(ushort))),
                        BitConverter.ToUInt16(buffer.Slice(0, sizeof(ushort))),
                        BitConverter.ToUInt16(buffer.Slice(6, sizeof(ushort))),
                        BitConverter.ToUInt16(buffer.Slice(4, sizeof(ushort)))
                    );

                    // cache the result
                    _cache.Set(nameof(GetVersion), version);
                }
                catch
                {
                    version = new Version("0.0.0.0");
                }
            }

            return version;
        }

        public void Stop()
        {
            Log.Information("Suspending xbox execution.");
            Session.SendCommand("stop");
        }

        public void Go()
        {
            Log.Information("Resuming xbox execution.");
            Session.SendCommand("go");
        }

        /// <summary>
        /// Calls an Xbox function.
        /// </summary>
        /// <param name="address">The function address.</param>
        /// <param name="args">The function arguments.</param>
        /// <returns>Returns an object that unboxes eax by default, but allows for reading st0 for floating-point return values.</returns>
        public uint Call(long address, params object[] args)
        {
            // TODO: call context (~4039+ which requires qwordparam)

            // injected script pushes arguments in reverse order for simplicity, this corrects that
            var reversedArgs = args.Reverse().ToArray();

            StringBuilder command = new StringBuilder();
            command.AppendFormat("funccall addr={0} ", address);
            for (int i = 0; i < reversedArgs.Length; i++)
            {
                command.AppendFormat("arg{0}={1} ", i, Convert.ToUInt32(reversedArgs[i]));
            }

            var returnValues = Connection.ParseKvpResponse(Session.SendCommandStrict(command.ToString()).Message);
            return (uint)returnValues["eax"];
        }

        /// <summary>
        /// Original Xbox Debug Monitor runtime patches.
        /// Prevents crashdumps from being written to the HDD and enables remote code execution.
        /// </summary>
        /// <param name="target"></param>
        private MemoryRegion PatchXbdm(Xbox target)
        {
            // the spin routine to be patched in after the signature patterns
            // spin:
            // jmp spin
            // int 3
            var spinBytes = new byte[] { 0xEB, 0xFE, 0xCC };

            // prevent crashdumps from being written to the hard drive by making it spin instead
            Log.Information("Disabling crashdump functionality.");
            if (target.Signatures.ContainsKey("ReadWriteOneSector"))
            {
                target.WriteMemory(target.Signatures["ReadWriteOneSector"] + 9, spinBytes);
            }
            else if (target.Signatures.ContainsKey("WriteSMBusByte"))
            {
                // this will prevent the LED state from changing upon crash
                target.WriteMemory(target.Signatures["WriteSMBusByte"] + 9, spinBytes);
            }
            else throw new Exception("Failed to disable crashdump!");

            Log.Information("Patching xbdm memory to enable remote code execution.");

            // store patches in the reloc section
            var relocInfo = target.GetModules().FirstOrDefault(m => m.Name.Equals("xbdm.dll")).GetSection(".reloc");

            // maintain next usable patch address and remaining size
            uint address = (uint)relocInfo.Base;
            int remainder = relocInfo.Size;

            #region HrFunctionCall Hook

            // 3424+ as it depends on sprintf within xbdm, earlier versions can possibly call against the kernel but their exports are different
            var asm = new Assembler(32);

            // data relative to function start
            var dataEndLabel = asm.CreateLabel();
            asm.jmp(dataEndLabel);  // short jump size of 2 bytes

            uint argThreadStringAddress = address + 2;
            var threadBytes = Encoding.ASCII.GetBytes("thread\0");
            asm.db(threadBytes);

            uint argAddrStringAddress = argThreadStringAddress + (uint)threadBytes.Length;
            var addrBytes = Encoding.ASCII.GetBytes("addr\0");
            asm.db(addrBytes);

            uint argFormatStringAddress = argAddrStringAddress + (uint)addrBytes.Length;
            var argFormatBytes = Encoding.ASCII.GetBytes("arg%01d\0");
            asm.db(argFormatBytes);

            uint returnFormatAddress = argFormatStringAddress + (uint)argFormatBytes.Length;
            var returnFormatBytes = Encoding.ASCII.GetBytes("eax=0x%X\0");
            asm.db(returnFormatBytes);
            asm.Label(ref dataEndLabel);

            // prolog
            asm.push(ebp);
            asm.mov(ebp, esp);
            asm.sub(esp, 0x10); // carve out space for local temp variables
            asm.pushad();

            // disable write protection globally, otherwise checked kernel calls may fail when writing to the default scratch space
            asm.mov(eax, cr0);
            asm.and(eax, 0xFFFEFFFF);
            asm.mov(cr0, eax);

            // arguments
            var commandPtr = ebp + 0x8;
            var responseAddress = ebp + 0xC;

            // local variables
            var temp = ebp - 0x4;
            var callAddress = ebp - 0x8;
            var argNameTerminator = ebp - 0xC;
            var argName = ebp - 0x10;

            // check for thread id
            asm.lea(eax, temp);
            asm.push(eax);
            asm.push(argThreadStringAddress);    // 'thread', 0
            asm.push(__dword_ptr[commandPtr]);
            asm.call((uint)target.Signatures["FGetDwParam"]);
            asm.test(eax, eax);
            var immediateCallLabel = asm.CreateLabel();
            asm.je(immediateCallLabel);

            // call original code if thread id exists
            asm.push(__dword_ptr[temp]);
            asm.call((uint)target.Signatures["DmSetupFunctionCall"]);
            var doneLabel = asm.CreateLabel();
            asm.jmp(doneLabel);

            // thread argument doesn't exist, must be an immediate call instead
            asm.Label(ref immediateCallLabel);

            // get the call address
            asm.lea(eax, __dword_ptr[callAddress]);
            asm.push(eax);
            asm.push(argAddrStringAddress);    // 'addr', 0
            asm.push(__dword_ptr[commandPtr]);
            asm.call((uint)target.Signatures["FGetDwParam"]);
            asm.test(eax, eax);
            var errorLabel = asm.CreateLabel();
            asm.je(errorLabel);

            // push arguments (leave it up to caller to reverse argument order and supply the correct amount)
            asm.xor(edi, edi);
            var nextArgLabel = asm.CreateLabel();
            var noMoreArgsLabel = asm.CreateLabel();
            asm.Label(ref nextArgLabel);
            {
                // get argument name
                asm.push(edi);                                  // argument index
                asm.push(argFormatStringAddress);                // format string address
                asm.lea(eax, __dword_ptr[argName]);          // argument name address
                asm.push(eax);
                asm.call((uint)target.Signatures["sprintf"]);
                asm.add(esp, 0xC);

                // check if it's included in the command
                asm.lea(eax, __[temp]);                    // argument value address
                asm.push(eax);
                asm.lea(eax, __[argName]);                   // argument name address
                asm.push(eax);
                asm.push(__dword_ptr[commandPtr]);               // command
                asm.call((uint)target.Signatures["FGetDwParam"]);
                asm.test(eax, eax);
                asm.je(noMoreArgsLabel);

                // push it on the stack
                asm.push(__dword_ptr[temp]);
                asm.inc(edi);

                // move on to the next argument
                asm.jmp(nextArgLabel);
            }
            asm.Label(ref noMoreArgsLabel);

            // perform the call
            asm.call(__dword_ptr[callAddress]);

            // print response message
            asm.push(eax);                                  // integer return value
            asm.push(returnFormatAddress);                  // format string address
            asm.push(__dword_ptr[responseAddress]);         // response address
            asm.call((uint)target.Signatures["sprintf"]);
            asm.add(esp, 0xC);

            // success epilog
            asm.popad();
            asm.leave();
            asm.mov(eax, 0x2DB0000);
            asm.ret(0x10);

            // failure epilog
            asm.Label(ref errorLabel);
            asm.popad();
            asm.leave();
            asm.mov(eax, 0x82DB0000);
            asm.ret(0x10);

            // original epilog
            asm.Label(ref doneLabel);
            asm.popad();
            asm.leave();
            asm.ret(0x10);

            // inject RPC handler and hook, leaving the rest of the reloc section as scratch space
            int caveSize = asm.Hook(target, target.Signatures["HrFunctionCall"], address);
            address += (uint)caveSize;
            remainder -= caveSize;

            // 16-byte align the scratch base
            uint padding = ((address + 0xF) & 0xFFFFFFF0) - address;
            address += padding;
            remainder -= (int)padding;

            return new MemoryRegion(address, (uint)remainder);

            #endregion
        }

        public void ExpandScratchBuffer()
        {
            if (!_hasScratchReassigned)
            {
                uint scratchSize = 1024 * 1024;
                Log.Information("Expanding scratch buffer to {0} bytes.", scratchSize);
                uint scratch = (uint)Kernel.MmAllocateContiguousMemory((int)scratchSize);
                ScratchBuffer = new MemoryRegion(scratch, scratchSize);
                _hasScratchReassigned = true;
            }
        }

        public string GetDisassembly(long address, int length, bool tabPrefix = true, bool showBytes = false)
        {
            // read code from xbox memory
            byte[] code = Memory.ReadBytes(address, length);

            // disassemble valid instructions
            var decoder = Iced.Intel.Decoder.Create(32, code);
            decoder.IP = (ulong)address;
            var instructions = new List<Instruction>();
            while (decoder.IP < decoder.IP + (uint)code.Length)
            {
                var insn = decoder.Decode();
                if (insn.IsInvalid)
                    break;
                instructions.Add(insn);
            }

            // formatting options
            var formatter = new MasmFormatter();
            formatter.Options.FirstOperandCharIndex = 8;
            formatter.Options.SpaceAfterOperandSeparator = true;

            // convert to string
            var output = new StringOutput();
            var disassembly = new StringBuilder();
            bool firstInstruction = true;
            foreach (var instr in instructions)
            {
                // skip newline for the first instruction
                if (firstInstruction)
                {
                    firstInstruction = false;
                } else disassembly.AppendLine();

                // optionally indent
                if (tabPrefix)
                {
                    disassembly.Append('\t');
                }

                // output address
                disassembly.Append(instr.IP.ToString("X8"));
                disassembly.Append(' ');

                // optionally output instruction bytes
                if (showBytes)
                {
                    for (int i = 0; i < instr.Length; i++)
                        disassembly.Append(code[(int)(instr.IP - (ulong)address) + i].ToString("X2"));
                    int missingBytes = 10 - instr.Length;
                    for (int i = 0; i < missingBytes; i++)
                        disassembly.Append("  ");
                    disassembly.Append(' ');
                }

                // output the decoded instruction
                formatter.Format(instr, output);
                disassembly.Append(output.ToStringAndReset());
            }
            
            return disassembly.ToString();
        }

        public Dictionary<string, long> Signatures
        {
            get
            {
                var signatures = _cache.Get<Dictionary<string, long>>(nameof(Signatures));
                if (signatures == null)
                {
                    var resolver = new SignatureResolver
                    {
                        // NOTE: ensure patterns don't overlap with any hooks! that way we don't have to cache any states; simplicity at the expense of slightly less perf on connect

                        // universal pattern
                        new SodmaSignature("ReadWriteOneSector")
                        { 
                            // mov     ebp, esp
                            new OdmPattern(0x1, new byte[] { 0x8B, 0xEC }),

                            // mov     dx, 1F6h
                            new OdmPattern(0x3, new byte[] { 0x66, 0xBA, 0xF6, 0x01 }),

                            // mov     al, 0A0h
                            new OdmPattern(0x7, new byte[] { 0xB0, 0xA0 })
                        },

                        // universal pattern
                        new SodmaSignature("WriteSMBusByte")
                        { 
                            // mov     al, 20h
                            new OdmPattern(0x3, new byte[] { 0xB0, 0x20 }),

                            // mov     dx, 0C004h
                            new OdmPattern(0x5, new byte[] { 0x66, 0xBA, 0x04, 0xC0 }),
                        },

                        // universal pattern
                        new SodmaSignature("FGetDwParam")
                        { 
                            // jz      short 0x2C
                            new OdmPattern(0x15, new byte[] { 0x74, 0x2C }),

                            // push     20h
                            new OdmPattern(0x17, new byte[] { 0x6A, 0x20 }),

                            // mov      [ecx], eax
                            new OdmPattern(0x33, new byte[] { 0x89, 0x01 })
                        },

                        // universal pattern
                        new SodmaSignature("DmSetupFunctionCall")
                        {
                            // test     ax, 280h
                            new OdmPattern(0x45, new byte[] { 0x66, 0xA9, 0x80, 0x02 }),

                            // push     63666D64h
                            new OdmPattern(0x54, new byte[] { 0x68, 0x64, 0x6D, 0x66, 0x63 })
                        },

                        // early revisions
                        new SodmaSignature("HrFunctionCall")
                        {
                            // mov     eax, 80004005h
                            new OdmPattern(0x1B, new byte[] { 0xB8, 0x05, 0x40, 0x00, 0x80 }),

                            // mov     ebx, 10008h
                            new OdmPattern(0x46, new byte[] { 0xBB, 0x08, 0x00, 0x01, 0x00 })
                        },

                        // later revisions
                        new SodmaSignature("HrFunctionCall")
                        {
                            // mov     eax, 80004005h
                            new OdmPattern(0x1B, new byte[] { 0xB8, 0x05, 0x40, 0x00, 0x80 }),

                            // mov     ebx, 10008h
                            new OdmPattern(0x45, new byte[] { 0xBB, 0x08, 0x00, 0x01, 0x00 })
                        },

                        // xbdm 3424+ contains this (3223 does not, who knows what inbetween does) whereas some early kernel versions do not? or have different kernel export tables for alpha/dvt3/dvt4/dvt6 etc.
                        new SodmaSignature("sprintf")
                        {
                            // mov     esi, [ebp+arg_0]
                            new OdmPattern(0x7, new byte[] { 0x8B, 0x75, 0x08 }),
                    
                            // mov      [ebp+var_1C], 7FFFFFFFh
                            new OdmPattern(0x16, new byte[] { 0xC7, 0x45, 0xE4, 0xFF, 0xFF, 0xFF, 0x7F })
                        }
                    };

                    // read xbdm .text section
                    var xbdmTextSegment = GetModules().FirstOrDefault(m => m.Name.Equals("xbdm.dll")).GetSection(".text");
                    byte[] data = new byte[xbdmTextSegment.Size];
                    ReadMemory(xbdmTextSegment.Base, data);

                    // scan for signatures
                    signatures = resolver.Resolve(data, xbdmTextSegment.Base);

                    // cache the result indefinitely
                    _cache.Set(nameof(Signatures), signatures);
                }

                return signatures;
            }
        }

        #endregion

        #region IDisposable

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                if (_hasScratchReassigned)
                {
                    Kernel.MmFreeContiguousMemory(ScratchBuffer.Address);
                }
                Session?.Dispose();

                // TODO: set large fields to null

                _disposed = true;
            }
        }

        ~Xbox()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}
