using System;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;

namespace Sniffer
{
    public class interfaceMonitor
    {
        public delegate void newPacketEventHandler(Packet p);
        public event newPacketEventHandler newPacket;
        
        private const int IOC_VENDOR = 0x18000000;
        private const int IOC_IN = -2147483648;
        private const int SIO_RCVALL = -1744830463;
        
        private byte[] _buffer = new byte[65000];
        private Socket _sck;
        private IPAddress _ipAddress;

        public interfaceMonitor(IPAddress ipAddress)
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT && Environment.OSVersion.Version.Major < 5)
            {
                throw new NotSupportedException("The library need Windows NT Version && the version must be 5 or higher");
            }
            _ipAddress = ipAddress;
        }

        public interfaceMonitor(string ipAddress)
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT && Environment.OSVersion.Version.Major < 5)
            {
                throw new NotSupportedException("The library need Windows NT Version && the version must be 5 or higher");
            }
            if (!IPAddress.TryParse(ipAddress, out _ipAddress))
            {
                throw new ArgumentException(
                    String.Format("The argument {0} is not a valid IP", _ipAddress)
                    );
            }
        }

        public interfaceMonitor Start()
        {

            try
            {
                _sck = new Socket(
                    AddressFamily.InterNetwork,
                    SocketType.Raw,
                    ProtocolType.IP
                    );
                _sck.Bind(
                    new IPEndPoint(_ipAddress, 0)
                    );

                _sck.IOControl(
                    SIO_RCVALL,
                    BitConverter.GetBytes(1),
                    null);

                setListener();
            }
            catch (Exception e)
            {
                //Do smth
            }
            return this;
        }

        private void setListener()
        {
            _sck.BeginReceive(
                    _buffer,
                    0,
                    _buffer.Length,
                    SocketFlags.None,
                    new AsyncCallback(onReceivePacket),
                    null
                    );
        }

        public interfaceMonitor Stop()
        {
            return this;
        }

        private void onReceivePacket(IAsyncResult asyncResult)
        {
            var content = new byte[_sck.EndReceive(asyncResult)];
            Array.Copy(_buffer, 0, content, 0, content.Length);
            
            newPacket
                (
                    new Packet(content, DateTime.Now)
                );
            setListener();
        }
    }
}
