using System.Diagnostics;

namespace OGXbdmDumper
{
    /// <summary>
    /// Xbox file information.
    /// </summary>
    [DebuggerDisplay("{Name}")]
    public class XboxFileInformation
    {
        /// <summary>
        /// The file name.
        /// </summary>
        public string Name => Path.GetFileName(FullName);

        /// <summary>
        /// The parent directory.
        /// </summary>
        public string Directory => Path.GetDirectoryName(FullName);

        /// <summary>
        /// The full file path and name.
        /// </summary>
        public string FullName;

        /// <summary>
        /// The file size.
        /// </summary>
        public long Size;

        /// <summary>
        /// The file attributes.
        /// </summary>
        public FileAttributes Attributes;

        /// <summary>
        /// The file creation time.
        /// </summary>
        public DateTime CreationTime;

        /// <summary>
        /// The file modification time.
        /// </summary>
        public DateTime ChangeTime;
    }
}
