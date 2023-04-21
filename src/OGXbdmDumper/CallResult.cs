namespace OGXbdmDumper
{
    /// <summary>
    /// The Xbox function call return value.
    /// </summary>
    public class CallResult
    {
        /// <summary>
        /// The integer result value.
        /// </summary>
        public uint Eax { get; }

        /// <summary>
        /// The floating-point result value.
        /// </summary>
        public float St0 { get; }

        /// <summary>
        /// A value used to uniquely identify a connection.
        /// </summary>
        public uint ConnectionId { get; }

        /// <summary>
        /// Constructs a call result.
        /// </summary>
        /// <param name="eax"></param>
        /// <param name="st0"></param>
        /// <param name="connectionId"></param>
        public CallResult(uint eax, uint st0, uint connectionId = 0)
        {
            Eax = eax;
            ConnectionId = (uint)(connectionId & ushort.MaxValue);

            byte[] data = new byte[4];
            using (MemoryStream ms = new MemoryStream(data))
            using (BinaryWriter bw = new BinaryWriter(ms))
            {
                bw.Write((uint)st0);
            }
            St0 = BitConverter.ToSingle(data, 0);
        }

        /// <summary>
        /// Returns the integer result value by default.
        /// </summary>
        /// <param name="result"></param>
        public static implicit operator uint(CallResult result)
        {
            return result.Eax;
        }
    }
}
