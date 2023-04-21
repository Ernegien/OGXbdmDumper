namespace OGXbdmDumper
{
    public class MemoryRegion
    {
        public uint Address { get; }
        public uint Size { get; }

        public MemoryRegion(uint address, uint size)
        { 
            Address = address;
            Size = size;
        }
    }
}
