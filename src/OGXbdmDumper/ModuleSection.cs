using System.Diagnostics;

namespace OGXbdmDumper
{
    /// <summary>
    /// TODO: description
    /// </summary>
    [DebuggerDisplay("{" + nameof(Name) + "}")]
    public class ModuleSection
    {
        /// <summary>
        /// TODO: description
        /// </summary>
        public string? Name;

        /// <summary>
        /// TODO: description
        /// </summary>
        public uint Base;

        /// <summary>
        /// TODO: description
        /// </summary>
        public int Size;

        /// <summary>
        /// TODO: description
        /// </summary>
        public uint Flags;
    }
}
