using System.Diagnostics;
using System.Text;

namespace OGXbdmDumper
{
    /// <summary>
    /// Provides streaming access to Xbox memory.
    /// </summary>
    public class XboxMemoryStream : Stream
    {
        #region Properties

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly Xbox _xbox;

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly BinaryReader _reader;
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private readonly BinaryWriter _writer;

        /// <summary>
        /// TODO: description
        /// </summary>
        public override long Position { get; set; }

        /// <summary>
        /// TODO: description
        /// </summary>
        public override bool CanRead => true;

        /// <summary>
        /// TODO: description
        /// </summary>
        public override bool CanSeek => true;

        /// <summary>
        /// TODO: description
        /// </summary>
        public override bool CanWrite => true;

        /// <summary>
        /// TODO: description
        /// </summary>
        public override bool CanTimeout => true;

        /// <summary>
        /// TODO: description
        /// </summary>
        public override int ReadTimeout => _xbox.ReceiveTimeout;

        /// <summary>
        /// TODO: description
        /// </summary>
        public override int WriteTimeout => _xbox.SendTimeout;

        #endregion

        #region Constructor

        /// <summary>
        /// TODO: description
        /// </summary>
        /// <param name="xbox"></param>
        public XboxMemoryStream(Xbox xbox)
        {
            _xbox = xbox ?? throw new ArgumentNullException(nameof(xbox));
            _reader = new BinaryReader(this);
            _writer = new BinaryWriter(this);
        }

        #endregion

        #region Methods

        /// <summary>
        /// TODO: description
        /// </summary>
        /// <param name="offset"></param>
        /// <param name="origin"></param>
        /// <returns></returns>
        public override long Seek(long offset, SeekOrigin origin)
        {
            switch (origin)
            {
                case SeekOrigin.Begin: return Position = offset; // zero-based address
                case SeekOrigin.Current: return Position += offset;
                default: throw new InvalidOperationException("Invalid SeekOrigin.");
            }
        }

        /// <summary>
        /// TODO: description
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <returns></returns>
        public override int Read(byte[] buffer, int offset, int count)
        {
            _xbox.ReadMemory(Position, buffer, offset, count);
            Position += count;  // have to manually increment count here since it's an external operation
            return count;
        }

        /// <summary>
        /// TODO: description
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        public override void Write(byte[] buffer, int offset, int count)
        {
            _xbox.WriteMemory(Position, buffer, offset, count);
            Position += count;  // have to manually increment count here since it's an external operation
        }

        #endregion

        #region Reads

        /// <summary>
        /// Reads a byte from the stream and advances the position of the stream by one byte.
        /// Throws an EndOfStreamException if the base stream returns -1 indicating the end of the stream.
        /// </summary>
        /// <returns></returns>
        public new byte ReadByte()
        {
            int val = _reader.ReadByte();
            if (val == -1) throw new EndOfStreamException();
            return (byte)val;
        }

        public bool ReadBool() => Convert.ToBoolean(_reader.ReadByte());
        public bool ReadBool(long position) { Position = position; return ReadBool(); }
        public sbyte ReadSByte() => _reader.ReadSByte();
        public sbyte ReadSByte(long position) { Position = position; return ReadSByte(); }
        public byte ReadByte(long position) { Position = position; return ReadByte(); }
        public short ReadInt16() => _reader.ReadInt16();
        public int ReadInt16(long position) { Position = position; return ReadInt16(); }
        public ushort ReadUInt16() => _reader.ReadUInt16();
        public ushort ReadUInt16(long position) { Position = position; return ReadUInt16(); }
        public int ReadInt32() => _reader.ReadInt32();
        public int ReadInt32(long position) { Position = position; return ReadInt32(); }
        public uint ReadUInt32() => _reader.ReadUInt32();
        public uint ReadUInt32(long position) { Position = position; return ReadUInt32(); }
        public long ReadInt64() => _reader.ReadInt64();
        public long ReadInt64(long position) { Position = position; return ReadInt64(); }
        public ulong ReadUInt64() => _reader.ReadUInt64();
        public ulong ReadUInt64(long position) { Position = position; return ReadUInt64(); }
        public float ReadSingle() =>  _reader.ReadSingle();
        public float ReadSingle(long position) { Position = position; return ReadSingle(); }
        public double ReadDouble() => _reader.ReadDouble();
        public double ReadDouble(long position) { Position = position; return ReadDouble(); }
        public string ReadAscii(int length) => Encoding.ASCII.GetString(_reader.ReadBytes(length));
        public string ReadAscii(long position, int length) { Position = position; return ReadAscii(length); }
        public string ReadUnicode(int length) => Encoding.Unicode.GetString(_reader.ReadBytes(length * sizeof(char)));
        public string ReadUnicode(long position, int length) { Position = position; return ReadUnicode(length); }
        public byte[] ReadBytes(int length) => _reader.ReadBytes(length);
        public byte[] ReadBytes(long position, int length) { Position = position; return _reader.ReadBytes(length); }

        /// <summary>
        /// Read a value of specified type from the stream.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="peek"></param>
        /// <returns></returns>
        public T Read<T>(bool peek = false) where T : struct
        {
            if (peek && !CanSeek)
                throw new NotSupportedException("Cannot peek a non-seekable stream.");

            long originalPosition = Position;

            try
            {
                return (Type.GetTypeCode(typeof(T))) switch
                {
                    TypeCode.Boolean => (T)(object)ReadBool(),
                    TypeCode.SByte => (T)(object)ReadSByte(),
                    TypeCode.Byte => (T)(object)ReadByte(),
                    TypeCode.Int16 => (T)(object)ReadInt16(),
                    TypeCode.UInt16 => (T)(object)ReadUInt16(),
                    TypeCode.Int32 => (T)(object)ReadInt32(),
                    TypeCode.UInt32 => (T)(object)ReadUInt32(),
                    TypeCode.Int64 => (T)(object)ReadInt64(),
                    TypeCode.UInt64 => (T)(object)ReadUInt64(),
                    TypeCode.Single => (T)(object)ReadSingle(),
                    TypeCode.Double => (T)(object)ReadDouble(),
                    _ => throw new NotSupportedException(),
                };
            }
            finally
            {
                if (peek)
                {
                    Position = originalPosition;
                }
            }
        }

        /// <summary>
        /// Read a value of specified type from the stream.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="position"></param>
        /// <param name="peek"></param>
        /// <returns></returns>
        public T Read<T>(long position, bool peek = false) where T : struct
        {
            Position = position;
            return Read<T>(peek);
        }

        public int Read(long position, Span<byte> buffer) { Position = position; return Read(buffer); }

        #endregion

        #region Writes

        public void Write(bool value) { WriteByte(Convert.ToByte(value)); }
        public void Write(long position, bool value) { Position = position; Write(value); }
        public void Write(byte value) { WriteByte(value); }
        public void Write(long position, byte value) { Position = position; Write(value); }
        public void Write(sbyte value) => _writer.Write(value);
        public void Write(long position, sbyte value) { Position = position; Write(value); }
        public void Write(short value) => _writer.Write(value);
        public void Write(long position, short value) { Position = position; Write(value); }
        public void Write(ushort value) => _writer.Write(value);
        public void Write(long position, ushort value) { Position = position; Write(value); }
        public void Write(int value) => _writer.Write(value);
        public void Write(long position, int value) { Position = position; Write(value); }
        public void Write(uint value) => _writer.Write(value);
        public void Write(long position, uint value) { Position = position; Write(value); }
        public void Write(long value) => _writer.Write(value);
        public void Write(long position, long value) { Position = position; Write(value); }
        public void Write(ulong value) => _writer.Write(value);
        public void Write(long position, ulong value) { Position = position; Write(value); }
        public void Write(float value) => _writer.Write(value);
        public void Write(long position, float value) { Position = position; Write(value); }
        public void Write(double value) => _writer.Write(value);
        public void Write(long position, double value) { Position = position; Write(value); }
        public void WriteAscii(string value) => _writer.Write(Encoding.ASCII.GetBytes(value));
        public void WriteAscii(long position, string value) { Position = position; WriteAscii(value); }
        public void WriteUnicode(string value) => _writer.Write(Encoding.Unicode.GetBytes(value));
        public void WriteUnicode(long position, string value) { Position = position; WriteUnicode(value); }

        #endregion

        #region Unsupported

        /// <summary>
        /// TODO: description. possibly remove exception and just do nothing
        /// </summary>
        public override void Flush() { throw new NotSupportedException(); }

        /// <summary>
        /// TODO: description. possibly return total memory size
        /// </summary>
        public override long Length { get { throw new NotSupportedException(); } }

        /// <summary>
        /// TODO: description
        /// </summary>
        /// <param name="value"></param>
        public override void SetLength(long value) { throw new NotSupportedException(); }

        #endregion
    }
}
