using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using FIDO_Detector.Fido_Support.ErrorHandling;
using FIDO_Detector.Fido_Support.Event_Queue;
using FIDO_Detector.Fido_Support.FidoDB;
using FIDO_Detector.Fido_Support.Hashing;
using FIDO_Detector.Fido_Support.Objects.Fido;
using FIDO_Detector.Fido_Support.Objects.Niddel;
using FIDO_Detector.Fido_Support.PreviousAlerts;
using FIDO_Detector.Fido_Support.RabbitMQ;
using FIDO_Detector.Fido_Support.Rest;
using Newtonsoft.Json;

namespace FIDO.Detectors.Niddel
{
  class DetectNiddel
  {
    public static void GetNiddelAlerts()
    {
      Console.WriteLine(@"Running Niddel v1 detector.");
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
      var parseConfigs = Object_Fido_Configs.ParseCouchDetectorConfigs(@"niddel");

      Parallel.ForEach(parseConfigs, conf =>
      {
        //var date = ReturnYesterday();
        var Days = Convert.ToInt16(conf.timer);
        var time = DateTime.Now.Hour;

        for (var i = 0; i >= -3; i--)
        {
          //if (!(time >= 12 & time < 13)) continue;
          string stringreturn = string.Empty;
          var date = ReturnRange(i);
          var request = conf.server +  conf.query[0].Replace(@"%currentdate%", date);
          var alertRequest = (HttpWebRequest) WebRequest.Create(request);
          alertRequest.Headers[@"X-API-KEY"] = Base64.Decode(conf.token);
          alertRequest.Method = @"GET";
          try
          {
            var getREST = new Fido_Rest_Connection();
            stringreturn = getREST.RestCall(alertRequest, false);
            if (stringreturn == null) continue;
            stringreturn = "{\"entries\":" + stringreturn + "}";
            var tempReturn = JsonConvert.DeserializeObject<Object_Niddel_Class>(stringreturn);
            var niddelRet = tempReturn.Alerts.OrderByDescending(x => x.BalScore).ToList();
            if (niddelRet.Capacity > 0)
            {
              ParseNiddelAlert(niddelRet);
            }

          }
          catch (Exception e)
          {
            Fido_EventHandler.SendEmail("Fido Error",
              "Fido Failed: {0} Exception caught in Niddel v1 Detector when getting json:" + e + @" " + stringreturn);
          }
        }
        Console.WriteLine(@"Finished processing Niddel events detector.");
      });
    }

    private static void ParseNiddelAlert(IEnumerable<NiddelAlert> retNiddelAlert)
    {
      var lFidoReturnValues = new FidoReturnValues();
      try
      {
        foreach (var alert in retNiddelAlert)
        {
          
        //Parallel.ForEach(retNiddelAlert, alert =>
        //{
          if (string.IsNullOrEmpty(alert.NetSrcIPrDomain))
            lFidoReturnValues = new FidoReturnValues
            {
              AlertID = alert.ID.ToString(),
              SrcIP = alert.NetSrcIP,
              CurrentDetector = "niddel",
              TimeOccured = Convert.ToDateTime(alert.Date + " " + alert.AggFirst).ToString("s"),
            };
          else
          {
            lFidoReturnValues = new FidoReturnValues
            {
              Hostname = alert.NetSrcIPrDomain,
              AlertID = alert.ID.ToString(),
              SrcIP = alert.NetSrcIP,
              CurrentDetector = "niddel",
              TimeOccured = Convert.ToDateTime(alert.Date + " " + alert.AggFirst).ToString("s"),
            };

          }

          if (alert.BalScore < 70) lFidoReturnValues.IsSendAlert = false;

          lFidoReturnValues.Niddel = new NiddelReturnValues
          {
            EventID = alert.ID.ToString(),
            EventTime = alert.Date + " " + alert.AggFirst,
            DstIp = alert.NetDstIP,
            NiddelAlert = alert
          };
          
          if (alert.NetDstIPDrDomain != null)
          {
            lFidoReturnValues.DNSName = alert.NetDstIPDrDomain.Replace(".", "(.)");
            if (alert.NetDstIPDrDomain != null)
            {
              lFidoReturnValues.Niddel.Domain = new List<string>();
              lFidoReturnValues.Niddel.Domain.Add(alert.NetDstIPDrDomain);
            }
            
            lFidoReturnValues.Domain = new List<string> { alert.NetDstIPDrDomain };
          }
          
          if (!PreviousAlerts.GetCouchPreviousHostAlert(lFidoReturnValues.Hash, lFidoReturnValues.Hostname, lFidoReturnValues.SrcIP, lFidoReturnValues.TimeOccured, lFidoReturnValues.DNSName))
          {
            continue;
          }


          lFidoReturnValues.DstIP = new List<string>() {alert.NetDstIP};

          if (alert.Matches.Any())
          {
            lFidoReturnValues.MalwareType = alert.Matches[0].Category ?? alert.Matches[0].Source ?? string.Empty;
          }
          else lFidoReturnValues.MalwareType = "Unknown";

          //Check to see if ID has been processed before
          var isRunDirector = false;
          //lFidoReturnValues.PreviousAlerts = Matrix_Historical_Helper.GetPreviousMachineAlerts(lFidoReturnValues, false);
          var retAlerts = PreviousAlerts.GetPreviousAlerts(lFidoReturnValues.AlertID);

          if (retAlerts != null)
          {
            lFidoReturnValues.OldAlerts = retAlerts.rows;
          }

          if (lFidoReturnValues.OldAlerts != null && lFidoReturnValues.OldAlerts.Count > 0)
          {
            isRunDirector = PreviousAlerts.PreviousAlert(lFidoReturnValues, lFidoReturnValues.AlertID, lFidoReturnValues.TimeOccured);
          }

          if (isRunDirector)
          {
            Console.WriteLine(@"Alert " + lFidoReturnValues.AlertID + @" already processed.");
          }
          else
          {
            lFidoReturnValues.IsTargetOS = true;
            var writeCouch = new Fido_CouchDB();
            var uuid  = writeCouch.WriteToDBFactory(lFidoReturnValues);
            var postmsg = new PostRabbit();
            postmsg.SendToRabbit(lFidoReturnValues.TimeOccured, uuid, Event_Queue.PrimaryConfig.hostdetection.whitelist.exchange, Event_Queue.PrimaryConfig.host, Event_Queue.PrimaryConfig);
            postmsg.SendToRabbit(lFidoReturnValues.TimeOccured, uuid, Event_Queue.PrimaryConfig.hostdetection.geoip.exchange, Event_Queue.PrimaryConfig.host, Event_Queue.PrimaryConfig);
          }
        //});
        }
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Niddel v1 Parser:" + e);
      }

    }

    private static string ReturnYesterday()
    {
      var getDate = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day);
      var getYesterDate = getDate.AddDays(-1);
      var date = getYesterDate.Year + "-" + getYesterDate.Month + "-" + getYesterDate.Day;
      return date;
    }

    private static string ReturnRange(int minusDay)
    {
      var getDate = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day);
      var getYesterDate = getDate.AddDays(minusDay);
      var date = getYesterDate.Year + "-" + getYesterDate.Month + "-" + getYesterDate.Day;
      return date;
    }

    private static bool PreviousAlert(FidoReturnValues lFidoReturnValues, string event_id, string event_time)
    {
      var isRunDirector = false;
      for (var j = 0; j < lFidoReturnValues.PreviousAlerts.Alerts.Rows.Count; j++)
      {
        if (lFidoReturnValues.PreviousAlerts.Alerts.Rows[j][6].ToString() != event_id) continue;
        if (Convert.ToDateTime(event_time) == Convert.ToDateTime(lFidoReturnValues.PreviousAlerts.Alerts.Rows[j][4]))
        {
          isRunDirector = true;
        }
      }
      return isRunDirector;
    }

  }
}
