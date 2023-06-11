using Serilog;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace OGXbdmDumper
{
    public class Connection : Stream
    {
        #region Properties

        private bool _disposed;

        private TcpClient _client;

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private static ReadOnlySpan<byte> NewLineBytes => new byte[] { (byte)'\r', (byte)'\n' };

        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private const string NewLineString = "\r\n";

        /// <summary>
        /// The binary reader for the session stream.
        /// </summary>
        public BinaryReader Reader { get; private set; }

        /// <summary>
        /// The binary writer for the session stream.
        /// </summary>
        public BinaryWriter Writer { get; private set; }

        /// <summary>
        /// Returns true if the session thinks it's connected based on the most recent operation.
        /// </summary>
        public bool IsConnected => _client.Connected;

        /// <summary>
        /// The time in milliseconds to wait while sending data before throwing a TimeoutException.
        /// </summary>
        public int SendTimeout { get => _client.SendTimeout; set => _client.SendTimeout = value; }

        /// <summary>
        /// The time in milliseconds to wait while receiving data before throwing a TimeoutException.
        /// </summary>
        public int ReceiveTimeout { get => _client.ReceiveTimeout; set => _client.ReceiveTimeout = value; }

        #endregion

        #region Construction

        /// <summary>
        /// Initializes the session.
        /// </summary>
        public Connection()
        {
            // initialize defaults
            Reader = new BinaryReader(this);
            Writer = new BinaryWriter(this);
            ResetTcp();
        }

        #endregion

        #region Methods

        /// <summary>
        /// Resets the internal TCP client state.
        /// </summary>
        private void ResetTcp()
        {
            // preserve previous settings or specify new defaults
            int sendTimeout = _client?.SendTimeout ?? 10000;
            int receiveTimeout = _client?.ReceiveTimeout ?? 10000;
            int sendBufferSize = _client?.SendBufferSize ?? 1024 * 1024 * 2;
            int receiveBufferSize = _client?.ReceiveBufferSize ?? 1024 * 1024 * 2;

            try
            {
                // attempt to disconnect
                _client?.Client?.Disconnect(false);
                _client?.Close();
                _client?.Dispose();
            }
            catch { /* do nothing */ }

            // initialize defaults
            _client = new TcpClient(AddressFamily.InterNetwork)
            {
                NoDelay = true,
                SendTimeout = sendTimeout,
                ReceiveTimeout = receiveTimeout,
                SendBufferSize = sendBufferSize,
                ReceiveBufferSize = receiveBufferSize
            };
        }

        /// <summary>
        /// Connects to the specified host and port.
        /// </summary>
        /// <param name="host">The host to connect to.</param>
        /// <param name="port">The port the host is listening on for the connection.</param>
        /// <param name="timeout">The time to wait in milliseconds for a connection to complete.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <exception cref="TimeoutException"></exception>
        /// <exception cref="SocketException"></exception>
        /// <exception cref="ObjectDisposedException"></exception>
        /// <exception cref="InvalidDataException"></exception>
        /// <exception cref="Exception"></exception>
        public ConnectionInfo Connect(string host, int port, int timeout = 500)
        {
            // argument checks
            if (host == null) throw new ArgumentNullException(nameof(host));
            if (port <= 0 || port > ushort.MaxValue) throw new ArgumentOutOfRangeException(nameof(port));
            if (timeout < 0) throw new ArgumentOutOfRangeException(nameof(timeout));
            if (_disposed) throw new ObjectDisposedException(nameof(Connection));

            Log.Information("Connecting to {0}.", host + ":" + port);
            if (!_client.ConnectAsync(host, port).Wait(timeout))
            {
                throw new TimeoutException("Failed to connect within the specified timeout period.");
            }
            Log.Information("Connected via {0}.", _client.Client.LocalEndPoint);

            // "201- connected\r\n"
            var response = ReceiveStatusResponse();
            if (!response.Success)
                throw new Exception(response.Full);

            // check connection quality
            var endpoint = _client.Client.RemoteEndPoint as IPEndPoint;
            var ping = new Ping().Send(endpoint.Address);
            if (ping.RoundtripTime > 1)
            {
                Log.Warning("Elevated network latency of {0}ms detected. Please have wired connectivity to your Xbox for fastest results.", ping.RoundtripTime);
            }

            return new ConnectionInfo(endpoint);
        }

        /// <summary>
        /// Closes the connection.
        /// </summary>
        public void Disconnect()
        {
            if (_disposed) throw new ObjectDisposedException(nameof(Connection));

            Log.Information("Disconnecting.");

            // avoid port exhaustion by attempting to gracefully inform the xbox we're leaving
            TrySendCommandText("bye");

            ResetTcp();
        }

        /// <summary>
        /// Waits for a single line of text to be available before receiving it.
        /// </summary>
        /// <param name="timeout">The optional receive timeout in milliseconds, overriding the session timeout.</param>
        /// <returns></returns>
        /// <exception cref="TimeoutException"></exception>
        /// <exception cref="ObjectDisposedException"></exception>
        /// <exception cref="SocketException"></exception>
        public string ReceiveLine(int? timeout = null)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(Connection));

            Stopwatch timer = Stopwatch.StartNew();
            Span<byte> buffer = stackalloc byte[1024];

            while ((timeout ?? ReceiveTimeout) == 0 || timer.ElapsedMilliseconds < (timeout ?? ReceiveTimeout))
            {
                Wait();

                // new line can't possibly exist
                if (_client.Available < NewLineBytes.Length) continue;

                // peek into the receive buffer for a new line
                int bytesRead = _client.Client.Receive(buffer, SocketFlags.Peek);
                int newLineIndex = buffer.Slice(0, bytesRead).IndexOf(NewLineBytes);

                // new line doesn't exist yet
                if (newLineIndex == -1) continue;

                // receive the line
                _client.Client.Receive(buffer.Slice(0, newLineIndex + NewLineBytes.Length));
                string line = Encoding.ASCII.GetString(buffer.Slice(0, newLineIndex).ToArray());
                Log.Verbose("Received line {0}.", line);
                return line;
            }

            throw new TimeoutException();
        }

        /// <summary>
        /// Receives multiple lines of text discarding the '.' delimiter at the end.
        /// </summary>
        /// <param name="timeout">The optional receive timeout in milliseconds, overriding the session timeout.</param>
        /// <returns></returns>
        /// <exception cref="TimeoutException"></exception>
        public List<string> ReceiveMultilineResponse(int? timeout = null)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(Connection));

            Log.Verbose("Receiving multiline response.");

            List<string> lines = new List<string>();

            string line;
            while ((line = ReceiveLine(timeout)) != ".")
            {
                lines.Add(line);
            }

            return lines;
        }

        /// <summary>
        /// Clears the specified amount of data from the receive buffer.
        /// </summary>
        /// <param name="size"></param>
        /// <exception cref="TimeoutException"></exception>
        /// <exception cref="ObjectDisposedException"></exception>
        /// <exception cref="SocketException"></exception>
        public void ClearReceiveBuffer(int size)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(Connection));

            if (size <= 0) return;

            Log.Verbose("Clearing {0} bytes from the receive buffer.", size);

            Span<byte> buffer = stackalloc byte[1024 * 80];

            while (size > 0)
            {
                size -= _client.Client.Receive(buffer.Slice(0, Math.Min(buffer.Length, size)));
            }
        }

        /// <summary>
        /// Clears all existing data from the receive buffer.
        /// </summary>
        public void ClearReceiveBuffer()
        {
            ClearReceiveBuffer(_client.Available);
        }

        /// <summary>
        /// Sends a command to the xbox without waiting for a response.
        /// </summary>
        /// <param name="command">Command to be sent</param>
        /// <param name="args">Arguments</param>
        /// <exception cref="TimeoutException"></exception>
        /// <exception cref="IOException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="SocketException"></exception>
        /// <exception cref="ObjectDisposedException"></exception>
        /// <exception cref="FormatException"></exception>
        public void SendCommandText(string command, params object[] args)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(Connection));

            // attempt to clean up the stream a bit; it's up to the caller to ensure this isn't ran while data is still being received
            ClearReceiveBuffer(_client.Available);
   
            string commandText = string.Format(command, args);
            Log.Verbose("Sending command {0}.", commandText);

            _client.Client.Send(Encoding.ASCII.GetBytes(commandText + NewLineString));
        }

        /// <summary>
        /// Attempts to send a command to the Xbox without waiting for a response.
        /// </summary>
        /// <param name="command">Command to be sent</param>
        /// <param name="args">Arguments</param>
        /// <returns>Returns true if successful.</returns>
        public bool TrySendCommandText(string command, params object[] args)
        {
            try
            {
                SendCommandText(command, args);
                return true;
            }
            catch (Exception e)
            {
                Log.Warning(e, "Command failure ignored.");
                return false;
            }
        }

        /// <summary>
        /// Sends a command to the xbox and returns the status response.
        /// Leaves error-handling up to the caller.
        /// </summary>
        /// <param name="command">Command to be sent</param>
        /// <param name="args">Arguments</param>
        /// <returns>Status response</returns>
        /// <exception cref="TimeoutException"></exception>
        /// <exception cref="InvalidDataException"></exception>
        /// <exception cref="SocketException"></exception>
        /// <exception cref="IOException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ObjectDisposedException"></exception>
        /// <exception cref="FormatException"></exception>
        public CommandResponse SendCommand(string command, params object[] args)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(Connection));

            SendCommandText(command, args);
            return ReceiveStatusResponse();
        }

        /// <summary>
        /// Sends a command to the xbox and returns the status response.
        /// An error response is rethrown as an exception.
        /// </summary>
        /// <param name="command">The command to be sent.</param>
        /// <param name="args">The formatted command arguments.</param>
        /// <returns>The status response.</returns>
        /// <exception cref="ObjectDisposedException"></exception>
        /// <exception cref="TimeoutException"></exception>
        /// <exception cref="InvalidDataException"></exception>
        /// <exception cref="SocketException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="IOException"></exception>
        /// <exception cref="FormatException"></exception>
        /// <exception cref="Exception">Throws varous other types when the command response indicates failure.</exception>
        public CommandResponse SendCommandStrict(string command, params object[] args)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(Connection));

            CommandResponse response = SendCommand(command, args);
            if (response.Success) return response;

            throw response.Code switch
            {
                // TODO: other error codes
                402 => new FileNotFoundException(response.Full),        // file not found
                407 => new NotSupportedException(response.Full),        // command not found
                410 => new IOException(response.Full),                  // file already exists
                411 => new IOException(response.Full),                  // directory not empty
                412 => new IOException(response.Full),                  // bad filename
                413 => new IOException(response.Full),                  // file cannot be created
                414 => new UnauthorizedAccessException(response.Full),  // access denied
                423 => new ArgumentException(response.Full),            // argument invalid
                _ => new Exception(response.Full),
            };
        }

        /// <summary>
        /// Receives a command for a status response to be received from the xbox.
        /// </summary>
        /// <param name="timeout">The optional receive timeout in milliseconds, overriding the XbdmSession Timeout.</param>
        /// <returns></returns>
        /// <exception cref="TimeoutException"></exception>
        /// <exception cref="InvalidDataException"></exception>
        /// <exception cref="ObjectDisposedException"></exception>
        /// <exception cref="SocketException"></exception>
        public CommandResponse ReceiveStatusResponse(int? timeout = null)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(Connection));

            string response = ReceiveLine(timeout);

            try
            {
                return new CommandResponse(response, Convert.ToInt32(response.Remove(3)), response.Remove(0, 5));
            }
            catch { throw new InvalidDataException("Invalid response."); }
        }

        /// <summary>
        /// Sleeps for the specified number of milliseconds unless the NoSleep session option is enabled, in which case it does nothing.
        /// </summary>
        public void Wait(int milliseconds = 1)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(Connection));

            if (milliseconds < 0) return;
        }

        #endregion

        #region Utilities

        /// <summary>
        /// Extracts key/value pairs from an Xbox response line.
        /// Values returned are either strings or UInt32's.
        /// Keys with a null value are considered flags.
        /// </summary>
        /// <param name="line"></param>
        /// <returns></returns>
        public static Dictionary<string, object> ParseKvpResponse(string line)
        {
            Dictionary<string, object> values = new Dictionary<string, object>();

            // remove any whitespace surrounding equals signs
            line = Regex.Replace(line, @"\s*([=+])\s*", "$1");

            // split by whitespace and commas, ignoring instances inside double quotes
            // ([^\s]+".*?[^\\]")|([^\s,]+)
            foreach (Match item in Regex.Matches(line, @"([^\s]+"".*?[^\\]"")|([^\s,]+)"))
            {
                // attempt to parse key value pair
                Match kvp = Regex.Match(item.Value, @"([^=]+)=(.+)");
                if (kvp.Success)
                {
                    string name = kvp.Groups[1].Value;
                    string value = kvp.Groups[2].Value;

                    if (value.StartsWith("\""))
                    {
                        // string
                        values[name] = value.Trim('"');
                    }
                    else if (value.StartsWith("0x"))
                    {
                        // hexidecimal integer
                        values[name] = Convert.ToUInt32(value, 16);
                    }
                    else if (uint.TryParse(value, out uint uintValue))
                    {
                        // decimal integer
                        values[name] = uintValue;
                    }
                    else
                    {
                        throw new InvalidCastException(line);
                    }
                }
                else
                {
                    // otherwise it must be a flag
                    values[item.Value] = null;
                }
            }

            return values;
        }

        #endregion

        #region Stream Implementation

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            // argument checks
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
            if (count <= 0) throw new ArgumentOutOfRangeException(nameof(count));
            if (_disposed) throw new ObjectDisposedException(nameof(Connection));

            // ensure it blocks for the full amount requested
            int bytesRead = 0;
            while (bytesRead < count)
            {
                bytesRead += _client.Client.Receive(buffer, offset + bytesRead, count - bytesRead, SocketFlags.None);
            }

            return bytesRead;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            // argument checks
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (offset < 0) throw new ArgumentOutOfRangeException(nameof(offset));
            if (count <= 0) throw new ArgumentOutOfRangeException(nameof(count));
            if (_disposed) throw new ObjectDisposedException(nameof(Connection));

            int bytesWritten = _client.Client.Send(buffer, offset, count, SocketFlags.None);

            // ensure all bytes are written
            if (bytesWritten != count)
                throw new Exception(string.Format("Partial write of {0} out of {1} bytes total.", bytesWritten, count));
        }

        /// <summary>
        /// Does nothing.
        /// </summary>
        public override void Flush()
        {

        }

        /// <summary>
        /// Not supported.
        /// </summary>
        /// <param name="offset"></param>
        /// <param name="origin"></param>
        /// <returns></returns>
        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Not supported.
        /// </summary>
        /// <param name="value"></param>
        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        #endregion

        #region IDisposable Implementation

        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                Disconnect();

                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }

                // TODO: set large fields to null
                _disposed = true;
            }
        }

        // TODO: override finalizer only if 'Dispose(bool disposing)' has code to free unmanaged resources
        ~Connection()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: false);
        }

        public new void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}