using Iced.Intel;
using System.Collections;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace OGXbdmDumper
{
    public static class Extensions
    {
        #region Misc

        /// <summary>
        /// Converts an Int32 into a Version.
        /// </summary>
        /// <param name="version"></param>
        /// <returns></returns>
        public static Version ToVersion(this int version)
        {
            return new Version(version & 0xFF, (version >> 8) & 0xFF,
                (version >> 16) & 0xFF, version >> 24);
        }

        #endregion

        #region String

        /// <summary>
        /// Extracts name/value pairs from an Xbox response line.
        /// </summary>
        /// <param name="line"></param>
        /// <returns></returns>
        public static Dictionary<string, object> ParseXboxResponseLine(this string line)
        {
            Dictionary<string, object> values = new Dictionary<string, object>();
            var items = Regex.Matches(line, @"(\S+)\s*=\s*(""(?:[^""]|"""")*""|\S+)");

            foreach (Match item in items)
            {
                string name = item.Groups[1].Value;
                string value = item.Groups[2].Value;

                long longValue;
                if (value.StartsWith("\""))
                {
                    // string
                    values[name] = value.Trim('"');
                }
                else if (value.StartsWith("0x"))
                {
                    // hexidecimal integer
                    values[name] = Convert.ToInt64(value, 16);
                }
                else if (long.TryParse(value, out longValue))
                {
                    // decimal integer
                    values[name] = longValue;
                }
                else
                {
                    throw new InvalidCastException("Unknown data type");
                }
            }

            return values;
        }

        #endregion

        #region Arrays

        /// <summary>
        /// Fills the specified byte array with random data.
        /// </summary>
        /// <param name="data"></param>
        /// <returns>Returns a reference of itself.</returns>
        public static byte[] FillRandom(this byte[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = (byte)Utility.Random.Next(byte.MaxValue);
            }
            return data;
        }

        /// <summary>
        /// Fills the specified byte array with random data.
        /// </summary>
        /// <param name="data"></param>
        /// <returns>Returns a reference of itself.</returns>
        public static Span<byte> FillRandom(this Span<byte> data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = (byte)Utility.Random.Next(byte.MaxValue);
            }
            return data;
        }

        /// <summary>
        /// Checks if the underlying data is equal.
        /// </summary>
        /// <param name="sourceData"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public static bool IsEqual(this byte[] sourceData, byte[] data)
        {
            return StructuralComparisons.StructuralEqualityComparer.Equals(sourceData, data);
        }

        /// <summary>
        /// Checks if the underlying data is equal.
        /// </summary>
        /// <param name="sourceData"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public static bool IsEqual(this Span<byte> sourceData, Span<byte> data)
        {
            return MemoryExtensions.SequenceEqual(sourceData, data);
        }

        /// <summary>
        /// TODO: description
        /// </summary>
        /// <param name="data"></param>
        /// <param name="pattern"></param>
        /// <param name="startIndex"></param>
        /// <returns></returns>
        public static int IndexOfArray(this byte[] data, byte[] pattern, int startIndex = 0)
        {
            for (int i = startIndex; i < data.Length; i++)
            {
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (data[i + j] != pattern[j])
                        break;

                    if (j == pattern.Length - 1)
                        return i;
                }
            }

            return -1;
        }

        #endregion

        #region Assembler

        /// <summary>
        /// Assembles the instructions.
        /// </summary>
        /// <param name="asm"></param>
        /// <param name="baseAddress"></param>
        /// <returns>Returns the assembled bytes.</returns>
        public static byte[] AssembleBytes(this Assembler asm, uint baseAddress)
        {
            using var ms = new MemoryStream();
            asm.Assemble(new StreamCodeWriter(ms), baseAddress);
            return ms.ToArray();
        }

        /// <summary>
        /// Hooks the specified Xbox target address redirecting to the specified cave address.
        /// Caller must recreate any instructions clobbered by the hook in the cave.
        /// The hook is 6 bytes long consisting of a push followed by a ret.
        /// </summary>
        /// <param name="asm">The assembler.</param>
        /// <param name="target">The xbox target.</param>
        /// <param name="hookAddress">The hook address.</param>
        /// <param name="caveAddress">The cave address.</param>
        public static void Hook(this Assembler asm, Xbox target, long hookAaddress, long caveAddress)
        {
            // store the pushret hook to the cave
            // TODO: combine writes!
            target.Memory.Position = hookAaddress;
            target.Memory.Write((byte)0x68);    // push
            target.Memory.Write(caveAddress);   // cave address
            target.Memory.Write((byte)0xC3);    // ret
        }

        #endregion

        #region Stream

        /// <summary>
        /// Copies the specified amount of data from the source to desination streams.
        /// Useful when at least one stream doesn't support the Length property.
        /// </summary>
        /// <param name="source">The source stream.</param>
        /// <param name="destination">The destination stream.</param>
        /// <param name="count">The amount of data to copy.</param>
        public static void CopyToCount(this Stream source, Stream destination, long count)
        {
            Span<byte> buffer = stackalloc byte[1024 * 80];

            while (count > 0)
            {
                var slice = buffer.Slice(0, (int)Math.Min(buffer.Length, count));

                // TODO: optimize via async queuing of reads/writes
                source.Read(slice);
                destination.Write(slice);

                count -= slice.Length;
            }
        }

        /// <summary>
        /// Writes a value to a stream.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="stream"></param>
        /// <param name="value"></param>
        /// <returns>Returns the number of bytes written.</returns>
        public static int Write<T>(this Stream stream, T value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));

            long origStreamPosition = stream.Position;
            using var writer = new BinaryWriter(stream);

            switch (Type.GetTypeCode(typeof(T)))
            {
                case TypeCode.Boolean:
                    writer.Write((bool)(object)value);
                    break;
                case TypeCode.Char:
                    writer.Write((char)(object)value);
                    break;
                case TypeCode.SByte:
                    writer.Write((sbyte)(object)value);
                    break;
                case TypeCode.Byte:
                    writer.Write((byte)(object)value);
                    break;
                case TypeCode.Int16:
                    writer.Write((short)(object)value);
                    break;
                case TypeCode.UInt16:
                    writer.Write((ushort)(object)value);
                    break;
                case TypeCode.Int32:
                    writer.Write((int)(object)value);
                    break;
                case TypeCode.UInt32:
                    writer.Write((uint)(object)value);
                    break;
                case TypeCode.Int64:
                    writer.Write((long)(object)value);
                    break;
                case TypeCode.UInt64:
                    writer.Write((ulong)(object)value);
                    break;
                case TypeCode.Single:
                    writer.Write((float)(object)value);
                    break;
                case TypeCode.Double:
                    writer.Write((double)(object)value);
                    break;
                case TypeCode.String:
                    writer.Write(Encoding.ASCII.GetBytes((string)(object)value));
                    break;
                default:

                    if (value is byte[])
                    {
                        writer.Write(value as byte[]);
                        break;
                    }

                    throw new InvalidCastException();
            }

            return (int)(stream.Position - origStreamPosition);
        }

        #endregion

        #region Hex Conversion

        /// <summary>
        /// TODO: description
        /// </summary>
        /// <param name="value"></param>
        /// <param name="padWidth"></param>
        /// <returns></returns>
        public static string ToHexString(this uint value, int padWidth = 0)
        {
            // TODO: cleanup
            return "0x" + value.ToString("X" + (padWidth > 0 ? padWidth.ToString() : string.Empty));
        }

        /// <summary>
        /// TODO: description
        /// </summary>
        /// <param name="value"></param>
        /// <param name="padWidth"></param>
        /// <returns></returns>
        public static string ToHexString(this int value, int padWidth = 0)
        {
            // TODO: cleanup
            return "0x" + value.ToString("X" + (padWidth > 0 ? padWidth.ToString() : string.Empty));
        }

        /// <summary>
        /// TODO: description
        /// </summary>
        /// <param name="value"></param>
        /// <param name="padWidth"></param>
        /// <returns></returns>
        public static string ToHexString(this long value, int padWidth = 0)
        {
            // TODO: cleanup
            return "0x" + value.ToString("X" + (padWidth > 0 ? padWidth.ToString() : string.Empty));
        }

        /// <summary>
        /// Converts an span array of bytes to a hexidecimal string representation.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string ToHexString(this byte[] data)
        {
            StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                hexString.Append(Convert.ToString(data[i], 16).ToUpperInvariant().PadLeft(2, '0'));
            }
            return hexString.ToString();
        }

        /// <summary>
        /// Converts an span array of bytes to a hexidecimal string representation.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string ToHexString(this Span<byte> data)
        {
            StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                hexString.Append(Convert.ToString(data[i], 16).ToUpperInvariant().PadLeft(2, '0'));
            }
            return hexString.ToString();
        }

        /// <summary>
        /// Converts an span array of bytes to a hexidecimal string representation.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string ToHexString(this ReadOnlySpan<byte> data)
        {
            StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                hexString.Append(Convert.ToString(data[i], 16).ToUpperInvariant().PadLeft(2, '0'));
            }
            return hexString.ToString();
        }

        /// <summary>
        /// Converts a hexidecimal string into byte format in the destination.
        /// </summary>
        /// <param name="str"></param>
        /// <param name="destination"></param>
        public static void FromHexString(this Span<byte> destination, string str)
        {
            if (str.Length == 0 || str.Length % 2 != 0)
                throw new ArgumentException("Invalid hexidecimal string length.");

            if (destination.Length != str.Length / 2)
                throw new ArgumentException("Invalid size.", nameof(destination));

            for (int i = 0; i < str.Length / 2; i++)
            {
                destination[i] = Convert.ToByte(str.Substring(i * 2, 2), 16);
            }
        }

        #endregion

        #region Reflection

        /// <summary>
        /// Gets the value of the specified member field or property.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="member"></param>
        /// <param name="obj"></param>
        /// <returns></returns>
        public static T GetValue<T>(this MemberInfo member, object obj)
        {
            return member.MemberType switch
            {
                MemberTypes.Field => (T)((FieldInfo)member).GetValue(obj),
                MemberTypes.Property => (T)((PropertyInfo)member).GetValue(obj),
                _ => throw new NotImplementedException(),
            };
        }

        /// <summary>
        /// Sets the value of the specified member field or property.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="member"></param>
        /// <param name="obj"></param>
        /// <param name="value"></param>
        public static void SetValue<T>(this MemberInfo member, object obj, T value)
        {
            switch (member.MemberType)
            {
                case MemberTypes.Field:
                    ((FieldInfo)member).SetValue(obj, value);
                    break;
                case MemberTypes.Property:
                    ((PropertyInfo)member).SetValue(obj, value);
                    break;
                default:
                    throw new NotImplementedException();
            }
        }

        #endregion
    }
}
