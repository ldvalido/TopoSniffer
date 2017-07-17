using System;
using System.Text;


namespace Sniffer
{
    public enum Precedence
    {
        Routine = 0,
        Priority = 1,
        Immediate = 2,
        Flash = 3,
        FlashOverride = 4,
        CRITICECP = 5,
        InternetworkControl = 6,
        NetworkControl = 7
    }

    public enum Delay
     {
        NormalDelay = 0,
        LowDelay = 1
     }

    public  enum Throughput
      {
        NormalThroughput = 0,
        HighThroughput = 1   
      }
      
    public enum Reliability
     {
        NormalReliability = 0,
        HighReliability = 1   
     }
      
    public enum Protocol{
        Ggp = 3,
        Icmp = 1,
        Idp = 22,
        Igmp = 2,
        IP = 4,
        ND = 77,
        Pup = 12,
        Tcp = 6,
        Udp = 17,
        Other = -1
    }
    
    public class Packet
    {
        #region Properties
        private byte[] _raw;
        private DateTime _time;
        private int _headerLength;
        private Precedence _precedence;
        private Delay _delay;
        private Protocol _protocol;
        private byte[] _checksum;
        
        private string _destinationAddress;
        private int _destinationPort;
        private int _identification;

        private Reliability _reliability;
        private string _sourceAddress;
        private int _sourcePort;
        private Throughput _throughput;
        private int _timeToLive;
        private int _totalLength;
        #endregion

        #region Public Properties

        public byte[] Raw
        {
            get { return _raw; }
        }

        public DateTime Time
        {
            get { return _time; }
        }

        public int HeaderLength
        {
            get { return _headerLength; }
        }

        public Precedence Precedence
        {
            get { return _precedence; }
        }

        public Delay Delay
        {
            get { return _delay; }
        }

        public Protocol Protocol
        {
            get { return _protocol; }
        }

        public string DestinationAddress
        {
            get { return _destinationAddress; }
        }

        public byte[] Checksum
        {
            get { return _checksum; }
        }

        public int DestinationPort
        {
            get { return _destinationPort; }
        }

        public int Identification
        {
            get { return _identification; }
        }

        public string SourceAddress
        {
            get { return _sourceAddress; }
        }

        public Reliability Reliability
        {
            get { return _reliability; }
        }

        public int SourcePort
        {
            get { return _sourcePort; }
        }

        public Throughput Throughput
        {
            get { return _throughput; }
        }

        public int TimeToLive
        {
            get { return _timeToLive; }
        }

        public int TotalLength
        {
            get { return _totalLength; }
        }

        #endregion

        public Packet(byte[] raw, DateTime time)
        {
            if (raw == null)
                throw new ArgumentNullException();
            
            if (raw.Length < 20)
                throw new ArgumentException();
            
            _raw = raw;
            _time = time;
            _headerLength = (raw[0] & 15) * 4;
            
            if ((raw[0] & 15) < 5)
                throw new ArgumentException();
            
            _precedence = (Precedence)((raw[1] & 14) >> 5);
            _delay = (Delay)((raw[1] & 16) >> 4);
            _throughput = (Throughput)((raw[1] & 8) >> 3);
            _reliability = (Reliability)((raw[1] & 4) >> 2);
            _totalLength = (raw[2] * 256) + raw[3];
            if (_totalLength != raw.Length)
                throw new ArgumentException();
            
            _identification = (raw[4] * 256) + raw[5];
            _timeToLive = raw[8];
            _protocol = (Protocol)raw[9];
            _checksum = new byte[3];
            _checksum[0] = raw[11];
            _checksum[1] = raw[10];
            try
            {
                _sourceAddress = GetIPAddress(raw, 12);
                _destinationAddress = GetIPAddress(raw, 16);
            }
            catch 
            {
                //ToDo Smth
            }
            if (_protocol == Protocol.Tcp | _protocol == Protocol.Udp)
            {
                _sourcePort = (raw[_headerLength] * 256) + raw[_headerLength + 1];
                _destinationPort = (raw[_headerLength + 2] * 256) + raw[_headerLength + 3];
            }
            else
            {
                _sourcePort = -1;
                _destinationPort = -1;
            }
        }

        string GetIPAddress(byte[] bArray, int nStart)
        {
            var returnValue = String.Empty;
            var tmp = new byte[4];
            if (bArray.Length > (nStart + 2))
            {
                tmp[0] = bArray[nStart];
                tmp[1] = bArray[nStart + 1];
                tmp[2] = bArray[nStart + 2];
                tmp[3] = bArray[nStart + 3];
            }
            returnValue =  String.Concat(
                    tmp[0].ToString() ,
                    "." ,
                    tmp[1].ToString(),
                    "." ,
                    tmp[2].ToString() ,
                    "." ,
                    tmp[3].ToString()
                );
            return returnValue;
        }

        #region ToString
        public override string  ToString()
        {
 	        return ToString(false);
        }
        
        public string ToString(bool rawData)
        {
            int i;
            var j = default(int);
            var sb = new StringBuilder(_raw.Length);
            if (rawData)
            {
                var rawLength = _raw.Length - 1;
                for (i = 0; i <= rawLength; i++)
                {
                    if (_raw[i] > 31)
                    {
                        sb.Append(_raw[i]);
                    }
                    else
                    {
                        sb.Append(".");
                    }
                }
            }
            else
            {
                var rawString = ToString(true);
                for (i = 0;i<_raw.Length -1;i+=16)
                {
                    for (j = i; j < _raw.Length - 1 && j < i + 16;j++ )
                        sb.Append(_raw[j].ToString("X2"));
                    sb.Append(" ");
                }
                if (rawString.Length < i + 16 )
                {
                    sb.Append(" " + ((16 - (rawString.Length % 16)) % 16) * 3);
                    sb.Append(" " + rawString.Substring(i) + Environment.NewLine);
                }else
                {
                    sb.Append(" " + rawString.Substring(i, 16) + Environment.NewLine);
                }
            }
            return sb.ToString();
        }
        #endregion
    }
}
