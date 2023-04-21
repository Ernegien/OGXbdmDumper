using Serilog;
using System.Collections.Concurrent;
using System.Collections;

namespace OGXbdmDumper
{
    /// <summary>
    /// Offset data mask pattern.
    /// </summary>
    public readonly struct OdmPattern
    {
        /// <summary>
        /// The offset from the presumed function start upon match.
        /// </summary>
        public readonly int Offset;

        /// <summary>
        ///The bitwise mask applied to the data when evaluating a match.
        /// </summary>
        public readonly ReadOnlyMemory<byte> Mask;

        /// <summary>
        /// The data to match.
        /// </summary>
        public readonly ReadOnlyMemory<byte> Data;

        /// <summary>
        /// Initializes a new offset data mask pattern.
        /// </summary>
        /// <param name="offset">The offset from the presumed function start upon match. Negative offsets are allowed.</param>
        /// <param name="data">The data to match.</param>
        /// <param name="mask">The bitwise mask applied to the data when evaluating a match.</param>
        public OdmPattern(int offset, ReadOnlyMemory<byte> data, ReadOnlyMemory<byte> mask)
        {
            Offset = offset;
            Data = data;
            Mask = mask;
        }

        /// <summary>
        /// Initializes a new offset data mask pattern; assumes a mask of all 1's.
        /// </summary>
        /// <param name="offset">The offset from the presumed function start upon match. Negative offsets are allowed.</param>
        /// <param name="data">The data to match.</param>
        public OdmPattern(int offset, ReadOnlyMemory<byte> data) :
            this(offset, data, Enumerable.Repeat(byte.MaxValue, data.Length).ToArray())
        { }

        public bool IsMatch(ReadOnlyMemory<byte> range, int offset)
        {
            // check if offset and data size are within range
            if (offset - Offset < 0 || offset + Offset + Data.Length > range.Length)
                return false;

            // compare with the pattern data and return false upon encountering a non-match
            ReadOnlySpan<byte> data = range.Span.Slice(offset + Offset, Data.Length);
            for (int i = 0; i < data.Length; i++)
            {
                if ((data[i] & Mask.Span[i]) != Data.Span[i])
                    return false;
            }

            return true;
        }
    }

    /// <summary>
    /// Simple offset data mask array signature containing a list of patterns.
    /// </summary>
    public class SodmaSignature : IEnumerable<OdmPattern>
    {
        private readonly List<OdmPattern> _patterns;

        /// <summary>
        /// The name of the function the signature is attempting to identify.
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// The pattern data size.
        /// </summary>
        public int Size => _patterns.Sum(p => p.Data.Length);

        /// <summary>
        /// The pattern data range.
        /// </summary>
        public int Range => _patterns.Max(p => p.Offset + p.Data.Length) - _patterns.Min(p => p.Offset);

        /// <summary>
        /// Initializes a new simple offset mask data array signature.
        /// </summary>
        /// <param name="name">The name of the function the signature is attempting to identify.</param>
        public SodmaSignature(string name)
        {
            _patterns = new List<OdmPattern>();
            Name = name;
        }

        public void Add(OdmPattern item)
        {
            // ensure mask and data are the same size
            if (item.Data.Length != item.Mask.Length)
                throw new NotSupportedException("Data and mask must be the same length");

            _patterns.Add(item);
        }

        public IEnumerator<OdmPattern> GetEnumerator()
        {
            return _patterns.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        public bool IsMatch(ReadOnlyMemory<byte> range, int offset)
        {
            foreach (var pattern in _patterns)
            {
                if (!pattern.IsMatch(range, offset))
                    return false;
            }

            return true;
        }
    }

    // TODO: don't make it IEnumerable, just have a Register function instead?
    /// <summary>
    /// 
    /// </summary>
    public class SignatureResolver : IEnumerable<SodmaSignature>
    {
        private readonly List<SodmaSignature> _signatures;

        /// <summary>
        /// Initializes a new simple offset mask data array signature resolver.
        /// </summary>
        public SignatureResolver()
        {
            _signatures = new List<SodmaSignature>();
        }

        public void Add(SodmaSignature item)
        {
            _signatures.Add(item);
        }

        public IEnumerator<SodmaSignature> GetEnumerator()
        {
            return _signatures.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        /// <summary>
        /// Resolves signature patterns against the specified memory range.
        /// Returns a dictionary of signature names and their respective absolute addresses.
        /// </summary>
        /// <param name="range"></param>
        /// <param name="baseAddress"></param>
        /// <returns></returns>
        public Dictionary<string, long> Resolve(ReadOnlyMemory<byte> range, long baseAddress = 0)
        {
            Log.Information("Resolving signatures in xbdm memory space.");

            // get matching signature addresses; signatures that match multiple addresses get assigned -1 to indicate failure
            var matches = new ConcurrentDictionary<SodmaSignature, long>();
            Parallel.ForEach(_signatures, sig =>
            {
                var r = range.Span;
                int maxOffset = range.Length - (sig.Max(p => p.Offset) + sig.Max(p => p.Data.Length));

                for (int i = sig.Min(p => p.Offset); i < maxOffset; i++)
                {
                    // account for negative offsets
                    if (i < 0) continue;

                    foreach (var pattern in sig)
                    {
                        for (int j = 0; j < pattern.Data.Length; j++)
                        {
                            if ((r[i + pattern.Offset + j] & pattern.Mask.Span[j]) != pattern.Data.Span[j])
                                goto nomatch;   // shut up
                        }
                    }

                    if (!matches.TryAdd(sig, baseAddress + i))
                    {
                        matches[sig] = -1;
                        Log.Error("Duplicate match for {0} signature at address {1}.", sig.Name, (baseAddress + i).ToHexString(8));
                    }
                    else Log.Information("Match for {0} signature at address {1}.", sig.Name, (baseAddress + i).ToHexString(8));

                    nomatch:;
                }
            });

            // when possible, resolve conflicts based on signature pattern size followed by largest offset range
            var resolved = new Dictionary<string, SodmaSignature>();
            foreach (var match in matches)
            {
                // ignore patterns with multiple matches
                if (match.Value == -1)
                    continue;

                // resolve different version signature conflicts
                if (resolved.ContainsKey(match.Key.Name))
                {
                    // match against the largest pattern size followed by largest offset range, otherwise unresolved
                    if (match.Key.Size > resolved[match.Key.Name].Size ||
                        ((match.Key.Size == resolved[match.Key.Name].Size) &&
                        match.Key.Range > resolved[match.Key.Name].Range))
                    {
                        resolved[match.Key.Name] = match.Key;
                    }
                    else
                    {
                        Log.Error("Unresolved conflict with {0} signature.", match.Key.Name);
                        resolved.Remove(match.Key.Name);
                    }
                }
                else resolved.Add(match.Key.Name, match.Key);
            }

            // translate to final name/address dictionary
            var result = new Dictionary<string, long>();
            foreach (var unique in resolved)
            {
                result.Add(unique.Key, matches[unique.Value]);
            }

            return result;
        }
    }
}
