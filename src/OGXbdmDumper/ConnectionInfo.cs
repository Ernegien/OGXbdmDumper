using Serilog;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace OGXbdmDumper
{
    public class ConnectionInfo
    {
        public IPEndPoint Endpoint { get; set; }
        public string? Name { get; set; }

        public ConnectionInfo(IPEndPoint endpoint, string? name = null)
        {
            Endpoint = endpoint;
            Name = name;
        }

        public static List<ConnectionInfo> DiscoverXbdm(int port, int timeout = 500)
        {
            Log.Information("Performing Xbox debug monitor network discovery broadcast on UDP port {Port}.", port);

            var connections = new List<ConnectionInfo>();
            byte[] datagramBuffer = new byte[1024];

            // iterate through each network interface
            Parallel.ForEach(NetworkInterface.GetAllNetworkInterfaces(), nic =>
            {
                // only worry about active IPv4 interfaces
                if (nic.OperationalStatus != OperationalStatus.Up || !nic.Supports(NetworkInterfaceComponent.IPv4))
                    return;

                // iterate through each ip address assigned to the interface
                Parallel.ForEach(nic.GetIPProperties().UnicastAddresses, ip =>
                {
                    // don't bother broadcasting from IPv6 or loopback addresses
                    if (ip.Address.AddressFamily == AddressFamily.InterNetworkV6 || IPAddress.IsLoopback(ip.Address))
                        return;

                    try
                    {
                        const short wildcardDiscoveryType = 3;

                        Log.Verbose("Broadcasting wildcard discovery packet from {IP} on interface {Name}",
                            $"{ip.Address}/{ip.PrefixLength}", nic.Name);

                        // broadcast wildcard discovery packet
                        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                        socket.EnableBroadcast = true;
                        socket.Bind(new IPEndPoint(ip.Address, 0));
                        socket.SendTo(BitConverter.GetBytes(wildcardDiscoveryType), new IPEndPoint(IPAddress.Broadcast, port));

                        // listen for any responses
                        var timer = Stopwatch.StartNew();
                        while (timer.ElapsedMilliseconds < timeout)
                        {
                            if (socket.Available == 0)
                            {
                                System.Threading.Thread.Sleep(1);
                                continue;
                            }

                            // receive the response
                            EndPoint endpoint = new IPEndPoint(IPAddress.Any, 0);
                            int bytesReceived = socket.ReceiveFrom(datagramBuffer, datagramBuffer.Length, SocketFlags.None, ref endpoint);

                            // perform some simple sanity checks to be more certain it was an xbox device that has responded and not some freak chance of nature
                            if (bytesReceived >= 2)
                            {
                                int nameLength = datagramBuffer[1];
                                if (datagramBuffer[0] == 2 && nameLength + 2 == bytesReceived)
                                {
                                    string xboxName = Encoding.ASCII.GetString(datagramBuffer, 2, nameLength);
                                    var foundXbox = new ConnectionInfo((IPEndPoint)endpoint, xboxName);

                                    // skip duplicates in the case that multiple ip addresses sharing the same subnet are assigned to an interface
                                    if (!connections.Contains(foundXbox))
                                    {
                                        Log.Information("Discovered an Xbox named {Name} at {Address}", foundXbox.Name, foundXbox.Endpoint);
                                        connections.Add(foundXbox);
                                    }
                                }
                            }

                            // reset the timer and keep listening for any additional responses
                            timer = Stopwatch.StartNew();
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Warning(ex, "An error has occurred during Xbox network discovery.");
                    }
                });
            });

            return connections;
        }
    }
}