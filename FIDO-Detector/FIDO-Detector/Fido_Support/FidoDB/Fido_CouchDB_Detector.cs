using System.Collections.Generic;
using System.IO;
using System.Windows.Forms;
using FIDO_Detector.Fido_Support.Objects.Fido;

namespace FIDO_Detector.Fido_Support.FidoDB
{
  class Fido_CouchDB_Detector
  {
    public string ReturnJson(FidoReturnValues lFidoReturnValues)
    {
      var prejson = string.Empty;
      var json = string.Empty;

      prejson = JsonDBFormat(lFidoReturnValues.DstIP, lFidoReturnValues.Hash, lFidoReturnValues.Domain, lFidoReturnValues.Url);

      switch (lFidoReturnValues.CurrentDetector)
      {
        case "carbonblack":
          json = prejson + '"' + "ThreatGRID" + '"' + ":" + SerializeJson.Serialize(lFidoReturnValues.CB.Alert.ThreatGRID) + "," + '"' + "VirusTotal" + '"' + ":" + SerializeJson.Serialize(lFidoReturnValues.CB.Alert.VirusTotal) + "}";
          break;

        case "cyphort":
          json = prejson + '"' + "ThreatGRID" + '"' + ":" + SerializeJson.Serialize(lFidoReturnValues.Cyphort.ThreatGRID) + "," + '"' + "VirusTotal" + '"' + ":" + SerializeJson.Serialize(lFidoReturnValues.Cyphort.VirusTotal) + "}";
          break;

        case "protectwise":
          json = prejson + '"' + "ThreatGRID" + '"' + ":" + SerializeJson.Serialize(lFidoReturnValues.ProtectWise.ThreatGRID) + "," + '"' + "VirusTotal" + '"' + ":" + SerializeJson.Serialize(lFidoReturnValues.ProtectWise.VirusTotal) + "}";
          break;

        case "niddel":
          json = prejson + '"' + "ThreatGRID" + '"' + ":" + SerializeJson.Serialize(lFidoReturnValues.Niddel.ThreatGRID) + "," + '"' + "VirusTotal" + '"' + ":" + SerializeJson.Serialize(lFidoReturnValues.Niddel.VirusTotal) + "}";
          break;
      }

      return json;
    }

    private string JsonDBFormat(List<string> DstIP, List<string> Hash, List<string> Domains, List<string> URLs)
    {
      var template = File.ReadAllText(Application.StartupPath + "\\media\\json\\threat_template.json");
      var sreplace = '"' + "DstIP" + '"' + ": [ ],";
      
      if (DstIP != null)
      {
        string newJson = string.Empty;

        for (int i = 0; i < DstIP.Count; i++)
        {
          if ((DstIP.Count -1) == i)
          {
            newJson += '"' + i.ToString() + '"' + ": " + '"' + DstIP[i] + '"';
          }
          else
          {
            newJson += '"' + i.ToString() + '"' + ": " + '"' + DstIP[i] + '"' + ",";
          }
        }

        template = template.Replace(sreplace, '"' + "DstIP" + '"' + ": [ { " + newJson + "} ],");
      }

      if (Hash != null)
      {
        string newJson = string.Empty;

        for (int i = 0; i < Hash.Count; i++)
        {
          if ((Hash.Count - 1) == i)
          {
            newJson += '"' + i.ToString() + '"' + ": " + '"' + Hash[i] + '"';
          }
          else
          {
            newJson += '"' + i.ToString() + '"' + ": " + '"' + Hash[i] + '"' + ",";
          }
        }

        template = template.Replace(sreplace, '"' + "Hash" + '"' + ": [ { " + newJson + "} ],");
      }

      if (Domains != null)
      {
        string newJson = string.Empty;

        for (int i = 0; i < Domains.Count; i++)
        {
          if ((Domains.Count - 1) == i)
          {
            newJson += '"' + i.ToString() + '"' + ": " + '"' + Domains[i] + '"';
          }
          else
          {
            newJson += '"' + i.ToString() + '"' + ": " + '"' + Domains[i] + '"' + ",";
          }
        }

        template = template.Replace(sreplace, '"' + "Domains" + '"' + ": [ { " + newJson + "} ],");
      }

      if (URLs != null)
      {
        string newJson = string.Empty;

        for (int i = 0; i < URLs.Count; i++)
        {
          if ((URLs.Count - 1) == i)
          {
            newJson += '"' + i.ToString() + '"' + ": " + '"' + URLs[i] + '"';
          }
          else
          {
            newJson += '"' + i.ToString() + '"' + ": " + '"' + URLs[i] + '"' + ",";
          }
        }

        template = template.Replace(sreplace, '"' + "URLs" + '"' + ": [ { " + newJson + "} ],");
      }

      return template;
    }
  }
}
