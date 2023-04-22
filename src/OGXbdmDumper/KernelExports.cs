namespace OGXbdmDumper
{
    /// <summary>
    /// TODO: description
    /// </summary>
    public class KernelExports
    {
        /// <summary>
        /// The Kernel export addresses;
        /// </summary>
        public long[] Addresses { get; }

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

        #endregion

        /// <summary>
        /// Index signifies ordinal number.
        /// </summary>
        /// <param name="addresses"></param>
        public KernelExports(long[] addresses, bool isBeta = false)
        {
            Addresses = addresses ?? throw new ArgumentNullException(nameof(addresses));
            HalReadSMBusValue = addresses[isBeta ? 339 : 45];
            NtClose = addresses[isBeta ? 183 : 187];
            NtDeviceIoControlFile = addresses[isBeta ? 192 : 196];
            NtOpenFile = addresses[isBeta ? 199 : 202];
            NtReadFile = addresses[isBeta ? 216 : 219];
            RtlFreeAnsiString = addresses[isBeta ? 282 : 286];
            RtlInitAnsiString = addresses[isBeta ? 285 : 289];
            XboxKrnlVersion = addresses[isBeta ? 316 : 324];
        }
    }
}
