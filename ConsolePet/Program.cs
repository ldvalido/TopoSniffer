using System.Net;

using Sniffer;
using System;

namespace ConsolePet
{
    class Program
    {
        static void Main(string[] args)
        {
            interfaceMonitor im = new interfaceMonitor("192.168.0.10");
            
            im.Start();
            im.newPacket += im_newPacket;
            while (true)
            {
                if (Console.ReadKey().KeyChar=='Q')
                    break;
            }
        }

        static void im_newPacket(Packet p)
        {
            if (p != null)
            {
                Console.WriteLine("IP Source: {0}, Ip Destiny: {1} ",
                    p.SourceAddress,
                    p.DestinationAddress);
            }
                
        }
    }
}
