using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace FIDO_Detector.Fido_Support.DNSLookup
{
  public class DNSLookup
  {
    public static List<string> DoGetHostEntry(string hostname)
    {
      IPHostEntry host;
      var ipReturn = new List<string>();

      try
      {
        host = Dns.GetHostEntry(hostname);
        foreach (IPAddress ip in host.AddressList)
        {
          ipReturn.Add(ip.ToString());
        }

      }
      catch (SocketException er)
      {
        if (er.ErrorCode == 11004)
        {
          return ipReturn;
        }
      }
      return ipReturn;
    }
  }
}
