using System.ComponentModel;
using System.Diagnostics;

namespace OGXbdmDumper
{
    /// <summary>
    /// An interface to the Xbox kernel.
    /// </summary>
    public class Kernel
    {
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly Xbox _xbox;

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private KernelExports? _exports;

        /// <summary>
        /// The file name.
        /// </summary>
        public const string Name = "xboxkrnl.exe";

        /// <summary>
        /// The kernel module information. Note: Internally caches result for future use.
        /// </summary>
        public readonly Module? Module;

        /// <summary>
        /// The kernel image size. NOTE: May not be contiguous memory.
        /// </summary>
        public int Size => Module == null ? 0 : Module.Size;

        /// <summary>
        /// The kernel base address in memory.
        /// </summary>
        public long Address => Module.BaseAddress;

        /// <summary>
        /// The kernel build time in UTC.
        /// </summary>
        public DateTime Date => Module.TimeStamp;

        /// <summary>
        /// The Xbox kernel build version.
        /// </summary>
        public Version Version => _xbox.Memory.ReadInt32(Exports.XboxKrnlVersion).ToVersion();

        /// <summary>
        /// The kernel exports. Note: Internally caches result for future use.
        /// </summary>
        public KernelExports Exports
        {
            get
            {
                if (_exports == null)
                {
                    // gets export table of offsets relative to kernel base address
                    long peBase = _xbox.Memory.ReadUInt32(Address + 0x3C);
                    long dataDirectory = _xbox.Memory.ReadUInt32(Address + peBase + 0x78);
                    int exportCount = _xbox.Memory.ReadInt32(Address + dataDirectory + 0x14);
                    long exportAddress = Address + _xbox.Memory.ReadUInt32(Address + dataDirectory + 0x1C);
                    byte[] exportBytes = _xbox.Memory.ReadBytes(exportAddress, exportCount * sizeof(uint));

                    // converts them to absolute addresses
                    long[] addresses = new long[exportCount + 1];
                    for (int i = 0; i < exportCount; i++)
                    {
                        long offset = BitConverter.ToUInt32(exportBytes, i * 4);
                        if (offset != 0)
                        {
                            addresses[i + 1] = Address + offset;
                        }
                    }

                    // generate exports
                    // TODO: beta detection
                    _exports = new KernelExports(addresses);
                }
                return _exports;
            }
        }

        /// <summary>
        /// Initializes communication with the Xbox kernel.
        /// </summary>
        /// <param name="xbox"></param>
        public Kernel(Xbox xbox)
        {
            _xbox = xbox ?? throw new ArgumentNullException(nameof(xbox));
            Module = _xbox.Modules.Find(m => m.Name == Name);
        }

        #region Exports

        public void HalReadSMBusValue(int address, int command, bool writeWord, uint valuePtr)
        {
            if (_xbox.Call(Exports.HalReadSMBusValue, address, command, writeWord, valuePtr).Eax != 0)
                throw new Exception();
        }

        public uint NtOpenFile(uint fileHandlePtr, uint desiredAccess, uint objectAttributesPtr, uint ioStatusBlockPtr, uint shareAccess, uint openOptions)
        {
            int status = (int)_xbox.Call(Exports.NtOpenFile, fileHandlePtr, desiredAccess, objectAttributesPtr, ioStatusBlockPtr, shareAccess, openOptions).Eax;
            if (status != 0)
                throw new Win32Exception(status);

            return _xbox.Memory.ReadUInt32(fileHandlePtr);
        }

        public void NtReadFile(uint fileHandlePtr, uint eventPtr, uint apcRoutinePtr, uint apcContextPtr, uint ioStatusBlockPtr, uint bufferPtr, uint length, uint byteOffsetPtr)
        {
            int status = (int)_xbox.Call(Exports.NtReadFile, fileHandlePtr, eventPtr, apcRoutinePtr, apcContextPtr, ioStatusBlockPtr, bufferPtr, length, byteOffsetPtr).Eax;
            if (status != 0)
                throw new Win32Exception(status);
        }

        public void NtClose(uint fileHandlePtr)
        {
            int status = (int)_xbox.Call(Exports.NtClose, fileHandlePtr).Eax;
            if (status != 0)
                throw new Win32Exception(status);
        }

        #endregion
    }
}
