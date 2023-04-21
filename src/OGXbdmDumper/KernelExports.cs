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

            // TODO: beta (DVT3) ordinals which might change between versions and require this logic be reworked
            HalReadSMBusValue = addresses[isBeta ? 0 : 45];
            NtClose = addresses[isBeta ? 0 : 187];
            NtDeviceIoControlFile = addresses[isBeta ? 0 : 196];
            NtOpenFile = addresses[isBeta ? 0 : 202];
            NtReadFile = addresses[isBeta ? 0 : 219];
            RtlFreeAnsiString = addresses[isBeta ? 0 : 286];
            RtlInitAnsiString = addresses[isBeta ? 0 : 289];
            XboxKrnlVersion = addresses[isBeta ? 0 : 324];
        }
    }
}
