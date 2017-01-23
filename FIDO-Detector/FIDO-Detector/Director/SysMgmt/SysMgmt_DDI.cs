using System;
using System.Net;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.FidoDB;
using Fido_Main.Fido_Support.Objects.DDI;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Fido_Support.Rest;
using Newtonsoft.Json;

namespace Fido_Main.Director.SysMgmt
{
  class SysMgmt_DDI
  {
    public static Object_DDI GetDDIRecord(FidoReturnValues lFidoReturnValues)
    {
      Console.WriteLine(@"Querying DDI for information.");
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      var parseConfigs = new SqLiteDB().GetDataTable("select * from configs_sysmgmt_ddi");

      var request = parseConfigs.Rows[0].ItemArray[3].ToString() + parseConfigs.Rows[0].ItemArray[4] + parseConfigs.Rows[0].ItemArray[5].ToString().Replace("%sip%", lFidoReturnValues.SrcIP);
      var alertRequest = (HttpWebRequest)WebRequest.Create(request);
      var ddiReturn = new Object_DDI();
      alertRequest.Headers[@"X-IPM-Username"] = parseConfigs.Rows[0].ItemArray[1].ToString();
      alertRequest.Headers[@"X-IPM-Password"] = parseConfigs.Rows[0].ItemArray[2].ToString();
      alertRequest.Method = "GET";
      try
      {
        var getREST = new Fido_Rest_Connection();
        var stringreturn = getREST.RestCall(alertRequest, false);
        if (string.IsNullOrEmpty(stringreturn)) return ddiReturn;
        stringreturn = "{\"entries\":" + stringreturn + "}";
        ddiReturn = JsonConvert.DeserializeObject<Object_DDI>(stringreturn);
        if (ddiReturn.DhcpEntries != null)
        {
          ddiReturn = ParseDDIReturn(ddiReturn, lFidoReturnValues);
        }
        Console.WriteLine(@"Finished getting DDI DHCP information.");
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in DDI section:" + e);
      }

      return ddiReturn;
    }

    private static Object_DDI ParseDDIReturn(Object_DDI ddiReturn, FidoReturnValues lFidoReturnValues)
    {

      for (int i = 0; i < ddiReturn.DhcpEntries.Count; i++)
      {
        ddiReturn.DhcpEntries[i].DhcpLeaseTime = FromEpochTime(ddiReturn.DhcpEntries[i].DhcpLeaseTime).ToString();
        ddiReturn.DhcpEntries[i].DhcpLeaseEndTime = FromEpochTime(ddiReturn.DhcpEntries[i].DhcpLeaseEndTime).ToString();
      }

      return ddiReturn;
    }

    private static DateTime? FromEpochTime(string unixTime)
    {
      return new DateTime(1970, 1, 1, 0, 0, 0).AddSeconds(Convert.ToDouble(unixTime));
    }
  }

}
