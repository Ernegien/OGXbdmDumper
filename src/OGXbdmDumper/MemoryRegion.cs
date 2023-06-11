namespace OGXbdmDumper
{
    public class MemoryRegion
    {
        public uint Address { get; }
        public int Size { get; }

        public MemoryRegion(uint address, int size)
        { 
            Address = address;
            Size = size;
        }
    }
}
