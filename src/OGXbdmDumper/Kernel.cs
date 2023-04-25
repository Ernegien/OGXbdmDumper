using Serilog.Events;
using Serilog;
using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using PeNet;

namespace OGXbdmDumper
{
    /// <summary>
    /// An interface to the Xbox kernel.
    /// </summary>
    public class Kernel
    {
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly Xbox _xbox;

        /// <summary>
        /// The file name.
        /// </summary>
        public const string Name = "xboxkrnl.exe";

        /// <summary>
        /// The kernel module information. Note: Internally caches result for future use.
        /// </summary>
        public readonly Module Module;

        /// <summary>
        /// The kernel image size. NOTE: May not be contiguous memory.
        /// </summary>
        public int Size => Module.Size;

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
        public Version Version { get; private set; }

        /// <summary>
        /// The kernel exports.
        /// </summary>
        public KernelExports Exports { get; private set; }

        /// <summary>
        /// Initializes communication with the Xbox kernel.
        /// </summary>
        /// <param name="xbox"></param>
        public Kernel(Xbox xbox)
        {
            _xbox = xbox ??
                throw new ArgumentNullException(nameof(xbox));

            Module = xbox.Modules.Find(m => m.Name == Name) ??
                throw new NullReferenceException(string.Format("Failed to load {0} module information!", Name));

            // TODO: remove 3rd-party dependency with proper PE parsing logic
            // grab enough of the kernel in memory to allow parsing it (possibly only need through the data section)
            var initSection = Module.Sections.Find(m => m.Name == "INIT");
            int size = (int)(initSection.Base - Address);
            var pe = new PeFile(_xbox.Memory.ReadBytes(Address, size));

            // resolve exports
            Exports = new KernelExports(Address, pe.ExportedFunctions);

            // get the version
            Version = xbox.Memory.ReadInt32(Exports.XboxKrnlVersion).ToVersion();

            // log export disassembly for debugging purposes when verbose is enabled
            if (Log.Logger.IsEnabled(LogEventLevel.Verbose))
            {
                foreach (PropertyInfo prop in Exports.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
                {
                    if (prop.Name.Equals("XboxKrnlVersion"))
                        continue;

                    Log.Verbose("{0} disassembly snippet." + Environment.NewLine + 
                        xbox.GetDisassembly(prop.GetValue<long>(Exports), 64).ToString(), prop.Name);
                }
            }
        }

        #region Exports

        public void HalReadSMBusValue(int address, int command, bool writeWord, uint valuePtr)
        {
            if (_xbox.Call(Exports.HalReadSMBusValue, address, command, writeWord, valuePtr) != 0)
                throw new Exception();
        }

        public uint NtOpenFile(uint fileHandlePtr, uint desiredAccess, uint objectAttributesPtr, uint ioStatusBlockPtr, uint shareAccess, uint openOptions)
        {
            int status = (int)_xbox.Call(Exports.NtOpenFile, fileHandlePtr, desiredAccess, objectAttributesPtr, ioStatusBlockPtr, shareAccess, openOptions);
            if (status != 0)
                throw new Win32Exception(status);

            return _xbox.Memory.ReadUInt32(fileHandlePtr);
        }

        public void NtReadFile(uint fileHandlePtr, uint eventPtr, uint apcRoutinePtr, uint apcContextPtr, uint ioStatusBlockPtr, uint bufferPtr, uint length, uint byteOffsetPtr)
        {
            int status = (int)_xbox.Call(Exports.NtReadFile, fileHandlePtr, eventPtr, apcRoutinePtr, apcContextPtr, ioStatusBlockPtr, bufferPtr, length, byteOffsetPtr);
            if (status != 0)
                throw new Win32Exception(status);
        }

        public void NtClose(uint fileHandlePtr)
        {
            int status = (int)_xbox.Call(Exports.NtClose, fileHandlePtr);
            if (status != 0)
                throw new Win32Exception(status);
        }

        /// <summary>
        /// Allocates physical memory.
        /// </summary>
        /// <param name="size">The allocation size.</param>
        /// <returns>Returns the allocation address, or zero if unsuccessful.</returns>
        public long MmAllocateContiguousMemory(int size)
        {
            return _xbox.Call(_xbox.Kernel.Exports.MmAllocateContiguousMemory, size);
        }

        /// <summary>
        /// Frees physical memory on the xbox.
        /// </summary>
        /// <param name="address">Memory address.</param>
        /// <returns>Returns true if successful.</returns>
        public bool MmFreeContiguousMemory(long address)
        {
            return _xbox.Call(_xbox.Kernel.Exports.MmFreeContiguousMemory, address) != 0;
        }

        #endregion
    }
}
