using Serilog;

namespace OGXbdmDumper
{
    public class ScratchBuffer
    {
        private bool _hasScratchReassigned;
        private Xbox _xbox;
        public MemoryRegion Region;

        public ScratchBuffer(Xbox xbox) 
        {
            _xbox = xbox ?? throw new ArgumentNullException(nameof(xbox));

            // get the xbdm reloc section info to be used as a scratch buffer
            var xbdm = xbox.Modules.Find(m => m.Name == "xbdm.dll") ?? throw new DllNotFoundException("xbdm.dll");
            var reloc = xbdm.GetSection(".reloc") ?? throw new NotSupportedException("Unable to allocate scratch space.");
            Region = new MemoryRegion(reloc.Base, reloc.Size);

            Log.Information("Using {0} bytes of scratch space at address {1}.",
                Region.Size.ToHexString(), Region.Address.ToHexString());
        }

        /// <summary>
        /// Allocates/writes data within the scratch buffer.
        /// </summary>
        /// <param name="data"></param>
        /// <returns>Returns the allocation address.</returns>
        public uint Alloc<T>(T data)
        {
            // keep track of the allocation address
            uint address = Region.Address;

            // write the data
            _xbox.Memory.Position = address;
            int bytesWritten = _xbox.Memory.Write(data);

            // calculate the new region size
            uint newAddress = (uint)(Region.Address + bytesWritten);
            int newSize = Region.Size - bytesWritten;
            if (newSize < 0) throw new OverflowException("Overflowed scratch space!");
            Region = new MemoryRegion(newAddress, newSize);

            // return the allocation address
            return address;
        }

        public void Align16()
        {
            uint padding = ((Region.Address + 0xF) & 0xFFFFFFF0) - Region.Address;
            Region = new MemoryRegion(Region.Address + padding, Region.Size - (int)padding);
        }

        public void Align4K()
        {
            uint padding = ((Region.Address + 0xFFF) & 0xFFFFF000) - Region.Address;
            Region = new MemoryRegion(Region.Address + padding, Region.Size - (int)padding);
        }
    }
}
