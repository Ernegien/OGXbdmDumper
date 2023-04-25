using PeNet.Header.Pe;

namespace OGXbdmDumper
{
    /// <summary>
    /// TODO: description
    /// </summary>
    public class KernelExports
    {
        private ExportFunction[] _functions;
        private readonly long _kernelBase;

        #region Exports

        /// <summary>
        /// 
        /// </summary>
        public long HalReadSMBusValue { get; }

        /// <summary>
        /// 
        /// </summary>
        public long NtClose { get; }

        /// <summary>
        /// 
        /// </summary>
        public long NtDeviceIoControlFile { get; }

        /// <summary>
        /// 
        /// </summary>
        public long NtOpenFile { get; }

        /// <summary>
        /// 
        /// </summary>
        public long NtReadFile { get; }

        /// <summary>
        /// 
        /// </summary>
        public long RtlFreeAnsiString { get; }

        /// <summary>
        /// 
        /// </summary>
        public long RtlInitAnsiString { get; }

        /// <summary>
        /// 
        /// </summary>
        public long XboxKrnlVersion { get; }

        /// <summary>
        /// 
        /// </summary>
        public long MmAllocateContiguousMemory { get; }

        /// <summary>
        /// 
        /// </summary>
        public long MmFreeContiguousMemory { get; }

        #endregion

        /// <summary>
        /// Index signifies ordinal number.
        /// </summary>
        /// <param name="kernelBase"></param>
        /// <param name="functions"></param>
        public KernelExports(long kernelBase, ExportFunction[] functions)
        {
            _kernelBase = kernelBase;
            _functions = functions;

            // TODO: guestimate, dvt4/retail seemed to have at least 366 whereas dvt3/beta around 345
            bool isBeta = functions.Length < 360;

            HalReadSMBusValue = Resolve(isBeta ? 339 : 45);
            NtClose = Resolve(isBeta ? 183 : 187);
            NtDeviceIoControlFile = Resolve(isBeta ? 192 : 196);
            NtOpenFile = Resolve(isBeta ? 199 : 202);
            NtReadFile = Resolve(isBeta ? 216 : 219);
            RtlFreeAnsiString = Resolve(isBeta ? 282 : 286);
            RtlInitAnsiString = Resolve(isBeta ? 285 : 289);
            XboxKrnlVersion = Resolve(isBeta ? 316 : 324);
            MmAllocateContiguousMemory = Resolve(isBeta ? 161 : 165);
            MmFreeContiguousMemory = Resolve(isBeta ? 166 : 171);
        }

        private long Resolve(int ordinal)
        {
            foreach (var function in _functions)
            {
                if (function.Ordinal == ordinal)
                    return _kernelBase + function.Address;
            }
            return 0;
        }
    }
}
