using System;
using System.Net;
using System.Text.RegularExpressions;
using Fido_Main.Director.VPN;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.Objects.ElasticSearch;
using Fido_Main.Fido_Support.Rest;
using Newtonsoft.Json;

namespace Fido_Main.Director.SysMgmt
{
  public class SysMgmt_ElasticSearch
  {
    public static Object_F5_VPN.ESVPN QueryESDB(string SrcIP, Enum_F5_VPN Type)
    {
      return null;
    }

    public static Object_F5_VPN.ESVPN QueryESDB(string SrcIP, string Common, Enum_F5_VPN Type)
    {
      var query = ESQuery(SrcIP, Common, Type);

      Console.WriteLine(@"Querying ES for VPN host/user.");

      var alertRequest = (HttpWebRequest) WebRequest.Create(query);
      var stringreturn = string.Empty;
      var esReturn = new Object_F5_VPN.ESVPN();

      try
      {
        var getREST = new Fido_Rest_Connection();
        stringreturn = getREST.RestCall(alertRequest, false);
        if (string.IsNullOrEmpty(stringreturn)) return esReturn;
        esReturn = JsonConvert.DeserializeObject<Object_F5_VPN.ESVPN>(stringreturn);
        return esReturn;
      }
      catch (WebException e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught querying ES:" + e);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught querying ES:" + e);
      }

      return esReturn;
    }

    private static string ESQuery(string SrcIp, string Common, Enum_F5_VPN Type)
    {
      var tempmonth = DateTime.Now.Month;
      var month = string.Empty;
      if (tempmonth.ToString().Length == 1)
      {
        month = @"0" + tempmonth;
      }
      else
      {
        month = tempmonth.ToString();
      }

      var sDate = DateTime.Now.Year + @"" + month;
      var index = @"vpnf5" + sDate;

      switch (Type)
      {
        case Enum_F5_VPN.IP:
          return @"http://es_itops.us-west-2.dynprod.netflix.net:7104/" + index + "/_search?q=" + '"' + "IPv4: " + SrcIp + '"' + "&size=100";
        case Enum_F5_VPN.Record:
          return @"http://es_itops.us-west-2.dynprod.netflix.net:7104/" + index + "/_search?q=" + '"' + Common + '"' + " AND (\"01490005\" OR \"01490128\" OR \"01490102\" OR \"01490248\" OR \"01490010\" OR \"01490500\" OR \"01490506\")";

        default:
          throw new Exception();
      }
    }

    public static string ParseQueryReturn(string Msg, string Pattern)
    {
      var regex = new Regex(Pattern, RegexOptions.Singleline);
      var regreturn = regex.Match(Msg);
      return regreturn.Value;
    }

    public static string ParseQueryReturn(string Msg, Object_F5_VPN_Search Pattern)
    {
      var regex = new Regex(Pattern.Value, RegexOptions.Singleline);
      var regreturn = regex.Match(Msg);
      return regreturn.Value;
    }
  }
}
