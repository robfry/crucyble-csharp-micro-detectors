using System;
using System.Net;
using FIDO.Detector.Fido_Support.Event_Queue;
using FIDO_Detector.Fido_Support.ErrorHandling;
using FIDO_Detector.Fido_Support.Rest;
using Newtonsoft.Json;

namespace FIDO_Detector.Fido_Support.Event_Queue
{
  public class Event_Queue
  {
    public static Object_Event_Queue.PrimaryConfig PrimaryConfig { get { return QueConfigClean(); } }

    private static Object_Event_Queue.Queues GetQueues()
    {
      var query = "http://127.0.0.1:5984/fido_configs_queues/_design/queues/_view/map";
      var alertRequest = (HttpWebRequest)WebRequest.Create(query);
      var stringreturn = string.Empty;
      var cdbReturn = new Object_Event_Queue.Queues();

      try
      {
        var getREST = new Fido_Rest_Connection();
        stringreturn = getREST.RestCall(alertRequest, false);
        if (string.IsNullOrEmpty(stringreturn)) return cdbReturn;
        cdbReturn = JsonConvert.DeserializeObject<Object_Event_Queue.Queues>(stringreturn);
        return cdbReturn;
      }
      catch (WebException e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught querying CouchDB:" + e);
      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught querying CouchDB:" + e);
      }

      return cdbReturn;
    }

    public static Object_Event_Queue.PrimaryConfig QueConfigClean()
    {
      var Que = new Object_Event_Queue.Queues();

      Que = GetQueues();

      var que = new Object_Event_Queue.PrimaryConfig();

      que = Que.rows[0].key.queues.runtest ? Que.rows[0].key.queues.test : Que.rows[0].key.queues.production;
      if (que.globalconfig.ssl) que.host = Que.rows[0].key.queues.runtest ? Que.rows[0].key.queues.test.globalconfig.host : Que.rows[0].key.queues.production.globalconfig.host;
      else que.host = Que.rows[0].key.queues.runtest ? Que.rows[0].key.queues.test.globalconfig.host : Que.rows[0].key.queues.production.globalconfig.host;
      que.runtest = Que.rows[0].key.queues.runtest;
      return que;
    }

  }
}
