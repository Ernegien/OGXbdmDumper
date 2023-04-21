namespace OGXbdmDumper
{
    public static class Utility
    {
        /// <summary>
        /// Shared random number generator.
        /// </summary>
        public static Random Random = new Random();

        public static long FromHiLo(uint hi, uint lo)
        {
            return ((long)hi << 32) | lo;
        }
    }
}
