using System.Diagnostics;

namespace OGXbdmDumper
{
    /// <summary>
    /// TODO: description
    /// </summary>
    [DebuggerDisplay("{" + nameof(Name) + "}")]
    public class Module
    {
        /// <summary>
        /// Name of the module that was loaded.
        /// </summary>
        public string? Name;

        /// <summary>
        /// Address that the module was loaded to.
        /// </summary>
        public uint BaseAddress;

        /// <summary>
        /// Size of the module.
        /// </summary>
        public int Size;

        /// <summary>
        /// Time stamp of the module.
        /// </summary>
        public DateTime TimeStamp;

        /// <summary>
        /// Checksum of the module.
        /// </summary>
        public uint Checksum;

        /// <summary>
        /// Sections contained within the module.
        /// </summary>
        public List<ModuleSection>? Sections;

        /// <summary>
        /// Indicates whether or not the module uses TLS.
        /// </summary>
        public bool HasTls;

        /// <summary>
        /// Indicates whether or not the module is an Xbox executable.
        /// </summary>
        public bool IsXbe;

        /// <summary>
        /// Gets an Xbox module section by name.
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public ModuleSection? GetSection(string name)
        {
            return Sections?.FirstOrDefault(section => name.Equals(section?.Name));
        }
    }
}
