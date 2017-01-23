using System.Collections.Generic;

namespace FIDO_Detector.Fido_Support.API_Endpoints
{
  public class Object_API_Endpoints
  {
    
    public class Globalconfig
    {
      public string host { get; set; }
      public string port { get; set; }
      public bool ssl { get; set; }
      public bool auth { get; set; }
      public string id { get; set; }
      public string pwd { get; set; }
      public string key { get; set; }
    }

    public class Localconfig
    {
      public string host { get; set; }
      public string port { get; set; }
      public bool ssl { get; set; }
      public bool auth { get; set; }
      public string id { get; set; }
      public string pwd { get; set; }
      public string key { get; set; }
    }

    public class Replicator
    {
      public Localconfig localconfig { get; set; }
    }

    public class AppConfigs
    {
      public string email { get; set; }
      public string emailserver { get; set; }
      public string startup_configs { get; set; }
      public string integrations { get; set; }
    }

    public class Detectors
    {
      public string dbname { get; set; }
      public string detector_configs { get; set; }
      public string docid { get; set; }
      public string update { get; set; }
    }

    public class Scoring
    {
      public string dstip { get; set; }
      public string domain { get; set; }
      public string hash { get; set; }
      public string url { get; set; }
    }

    public class FidoConfigsDetectors
    {
      public string dbname { get; set; }
      public Localconfig localconfig { get; set; }
      public Detectors detectors { get; set; }
    }

    public class FidoConfigsHistoricalScoring
    {
      public string dbname { get; set; }
      public Localconfig localconfig { get; set; }
      public Scoring scoring { get; set; }
    }

    public class Configs
    {
      public string paired { get; set; }
    }

    public class FidoConfigsPostureAsset
    {
      public string dbname { get; set; }
      public Localconfig localconfig { get; set; }
      public Configs configs { get; set; } 
    }

    public class MachineConfigs
    {
      public string machine { get; set; }
    }

    public class FidoConfigsPostureMachine
    {
      public string dbname { get; set; }
      public Localconfig localconfig { get; set; }
      public MachineConfigs configs { get; set; }
    }

    public class UserConfigs
    {
      public string user { get; set; }
    }

    public class FidoConfigsPostureUser
    {
      public string dbname { get; set; }
      public Localconfig localconfig { get; set; }
      public UserConfigs configs { get; set; }
    }

    public class FidoConfigsServicenow
    {
      public string dbname { get; set; }
      public Localconfig localconfig { get; set; }
    }

    public class Sysmgmt
    {
      public string updates { get; set; }
      public string vendors { get; set; }
      public string sql { get; set; }
      public string labels { get; set; }
    }

    public class FidoConfigsSysmgmt
    {
      public string dbname { get; set; }
      public Localconfig localconfig { get; set; }
      public Sysmgmt sysmgmt { get; set; }
    }

    public class ThreatfeedApi
    {
      public string vendor { get; set; }
    }

    public class FidoConfigsThreatfeeds
    {
      public string dbname { get; set; }
      public Localconfig localconfig { get; set; }
      public ThreatfeedApi threatfeed_api { get; set; }
    }

    public class Threatfeeds
    {
      public string scoring { get; set; }
      public string feedweight { get; set; }
    }

    public class FidoConfigsThreatfeedsScoring
    {
      public string dbname { get; set; }
      public Localconfig localconfig { get; set; }
      public Threatfeeds threatfeeds { get; set; }
    }

    public class FidoConsole
    {
      public string dbname { get; set; }
      public Localconfig localconfig { get; set; }
    }

    public class Alerts
    {
      public string alertid { get; set; }
      public string hostname { get; set; }
      public string srcip { get; set; }
      public string timeoccurred { get; set; }
    }

    public class Detector
    {
      public string type { get; set; }
    }

    public class PreviousAlerts
    {
      public string domain { get; set; }
      public string dstip { get; set; }
      public string hash { get; set; }
      public string url { get; set; }
    }

    public class FidoEventsAlerts
    {
      public string dbname { get; set; }
      public Localconfig localconfig { get; set; }
      public Alerts alerts { get; set; }
      public Detector detector { get; set; }
      public PreviousAlerts previousalerts { get; set; }      
    }

    public class Whitelist
    {
      public string entries { get; set; }
    }

    public class FidoEventsWhitelist
    {
      public string dbname { get; set; }
      public Localconfig localconfig { get; set; }
      public Whitelist whitelist { get; set; }
    }

    public class FidoThreatfeeds
    {
      public string dbname { get; set; }
      public Localconfig localconfig { get; set; }
      public Threatfeeds threatfeeds { get; set; }
    }

    public class PrimaryConfig
    {
      public bool runtest { get; set; }
      public string host { get; set; }
      public Globalconfig globalconfig { get; set; }
      public Replicator _replicator { get; set; }
      public FidoConfigs fido_configs { get; set; }
      public FidoConfigsDetectors fido_configs_detectors { get; set; }
      public FidoConfigsHistoricalScoring fido_configs_historical_scoring { get; set; }
      public FidoConfigsPostureAsset fido_configs_posture_asset { get; set; }
      public FidoConfigsPostureMachine fido_configs_posture_machine { get; set; }
      public FidoConfigsPostureUser fido_configs_posture_user { get; set; }
      public FidoConfigsServicenow fido_configs_servicenow { get; set; }
      public FidoConfigsSysmgmt fido_configs_sysmgmt { get; set; }
      public FidoConfigsThreatfeeds fido_configs_threatfeeds { get; set; }
      public FidoConfigsThreatfeedsScoring fido_configs_threatfeeds_scoring { get; set; }
      public FidoConsole fido_console { get; set; }
      public FidoEventsAlerts fido_events_alerts { get; set; }
      public FidoEventsWhitelist fido_events_whitelist { get; set; }
      public FidoThreatfeeds fido_threatfeeds { get; set; }

      public class FidoConfigs
      {
        public string dbname { get; set; }
        public Localconfig localconfig { get; set; }
        public AppConfigs app_configs { get; set; }
      }

    }

    //public class Test
    //{
    //  public Globalconfig globalconfig { get; set; }
    //  public Replicator _replicator { get; set; }
    //  public FidoConfigs fido_configs { get; set; }
    //  public FidoConfigsDetectors fido_configs_detectors { get; set; }
    //  public FidoConfigsPostureAsset fido_configs_posture_asset { get; set; }
    //  public FidoConfigsPostureMachine fido_configs_posture_machine { get; set; }
    //  public FidoConfigsPostureUser fido_configs_posture_user { get; set; }
    //  public FidoConfigsServicenow fido_configs_servicenow { get; set; }
    //  public FidoConfigsSysmgmt fido_configs_sysmgmt { get; set; }
    //  public FidoConfigsThreatfeeds fido_configs_threatfeeds { get; set; }
    //  public FidoConfigsThreatfeedsScoring fido_configs_threatfeeds_scoring { get; set; }
    //  public FidoConsole fido_console { get; set; }
    //  public FidoEventsAlerts fido_events_alerts { get; set; }
    //  public FidoEventsWhitelist fido_events_whitelist { get; set; }
    //  public FidoThreatfeeds fido_threatfeeds { get; set; }
    //}

    public class Apicall
    {
      public bool runtest { get; set; }
      public PrimaryConfig production { get; set; }
      public PrimaryConfig test { get; set; }
    }

    public class Key
    {
      public string _id { get; set; }
      public string _rev { get; set; }
      public Apicall apicall { get; set; }
    }

    public class Row
    {
      public string id { get; set; }
      public Key key { get; set; }
      public object value { get; set; }
    }

    public class API
    {
      public int total_rows { get; set; }
      public int offset { get; set; }
      public List<Row> rows { get; set; }
    }
  }
}