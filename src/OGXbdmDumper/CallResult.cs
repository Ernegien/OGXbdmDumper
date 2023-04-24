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
        /// Constructs a call result.
        /// </summary>
        /// <param name="eax"></param>
        public CallResult(uint eax)
        {
            Eax = eax;
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
