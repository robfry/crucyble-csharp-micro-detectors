using System.Collections.Generic;

namespace FIDO.Detector.Fido_Support.Event_Queue
{
  public class Object_Event_Queue
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

    public class Hostdetection
    {
      public DHCP dhcp { get; set; }
      public GEOIP geoip { get; set; }
      public VPN vpn { get; set; }
      public Whitelist whitelist { get; set; }

      public class DHCP
      {
        public string exchange { get; set; }
        public DDI ddi { get; set; }

        public class DDI
        {
          public string queue { get; set; }
          public string durability { get; set; }
          public bool autodelete { get; set; }
          public string messagettl { get; set; }
          public string autoexpire { get; set; }
          public string maxlength { get; set; }
          public string deadletterex { get; set; }
          public string deadletterrt { get; set; }
          public string arguments { get; set; }
        }
      }
      public class GEOIP
      {
        public string exchange { get; set; }
        public Maxmind maxmind { get; set; }

        public class Maxmind
        {
          public string queue { get; set; }
          public string durability { get; set; }
          public bool autodelete { get; set; }
          public string messagettl { get; set; }
          public string autoexpire { get; set; }
          public string maxlength { get; set; }
          public string deadletterex { get; set; }
          public string deadletterrt { get; set; }
          public string arguments { get; set; }
        }
      }
      public class VPN
      {
        public string exchange { get; set; }
        public F5 f5 { get; set; }

        public class F5
        {
          public string queue { get; set; }
          public string durability { get; set; }
          public bool autodelete { get; set; }
          public string messagettl { get; set; }
          public string autoexpire { get; set; }
          public string maxlength { get; set; }
          public string deadletterex { get; set; }
          public string deadletterrt { get; set; }
          public string arguments { get; set; }
        }
      }
      public class Whitelist
      {
        public string exchange { get; set; }
        public string queue { get; set; }
        public string durability { get; set; }
        public bool autodelete { get; set; }
        public string messagettl { get; set; }
        public string autoexpire { get; set; }
        public string maxlength { get; set; }
        public string deadletterex { get; set; }
        public string deadletterrt { get; set; }
        public string arguments { get; set; }
      }

    }

    public class DataSources
    {
      public Inventory inventory { get; set; }

      public class Inventory
      {
        public string exchange { get; set; }
        public Landesk landesk { get; set; }
        public Jamf jamf { get; set; }
        public Sentinelone sentinelone { get; set; }
        public CarbonBlack carbonblack { get; set; }
        public ActiveDirectory activedirectory { get; set; }

        public class Landesk
        {
          public string exchange { get; set; }
          public string queue { get; set; }
          public string durability { get; set; }
          public bool autodelete { get; set; }
          public string messagettl { get; set; }
          public string autoexpire { get; set; }
          public string maxlength { get; set; }
          public string deadletterex { get; set; }
          public string deadletterrt { get; set; }
          public string arguments { get; set; }
        }

        public class Jamf
        {
          public string exchange { get; set; }
          public string queue { get; set; }
          public string durability { get; set; }
          public bool autodelete { get; set; }
          public string messagettl { get; set; }
          public string autoexpire { get; set; }
          public string maxlength { get; set; }
          public string deadletterex { get; set; }
          public string deadletterrt { get; set; }
          public string arguments { get; set; }
        }

        public class Sentinelone
        {
          public string exchange { get; set; }
          public string queue { get; set; }
          public string durability { get; set; }
          public bool autodelete { get; set; }
          public string messagettl { get; set; }
          public string autoexpire { get; set; }
          public string maxlength { get; set; }
          public string deadletterex { get; set; }
          public string deadletterrt { get; set; }
          public string arguments { get; set; }
        }

        public class CarbonBlack
        {
          public string exchange { get; set; }
          public string queue { get; set; }
          public string durability { get; set; }
          public bool autodelete { get; set; }
          public string messagettl { get; set; }
          public string autoexpire { get; set; }
          public string maxlength { get; set; }
          public string deadletterex { get; set; }
          public string deadletterrt { get; set; }
          public string arguments { get; set; }
        }

        public class ActiveDirectory
        {
          public string exchange { get; set; }
          public string queue { get; set; }
          public string durability { get; set; }
          public bool autodelete { get; set; }
          public string messagettl { get; set; }
          public string autoexpire { get; set; }
          public string maxlength { get; set; }
          public string deadletterex { get; set; }
          public string deadletterrt { get; set; }
          public string arguments { get; set; }
        }
      }
    }

    public class Notifications
    {
      public string exchange { get; set; }
      public string queue { get; set; }
      public string durability { get; set; }
      public bool autodelete { get; set; }
      public string messagettl { get; set; }
      public string autoexpire { get; set; }
      public string maxlength { get; set; }
      public string deadletterex { get; set; }
      public string deadletterrt { get; set; }
      public string arguments { get; set; }
    }

    public class Threatfeeds
    {
      public Opendns opendns { get; set; }
      public Threatgrid threatgrid { get; set; }
      public Vt vt { get; set; }

      public class Opendns
      {
        public string exchange { get; set; }
        public string queue { get; set; }
        public string durability { get; set; }
        public bool autodelete { get; set; }
        public string messagettl { get; set; }
        public string autoexpire { get; set; }
        public string maxlength { get; set; }
        public string deadletterex { get; set; }
        public string deadletterrt { get; set; }
        public string arguments { get; set; }
      }

      public class Threatgrid
      {
        public string exchange { get; set; }
        public string queue { get; set; }
        public string durability { get; set; }
        public bool autodelete { get; set; }
        public string messagettl { get; set; }
        public string autoexpire { get; set; }
        public string maxlength { get; set; }
        public string deadletterex { get; set; }
        public string deadletterrt { get; set; }
        public string arguments { get; set; }
      }

      public class Vt
      {
        public string exchange { get; set; }
        public string queue { get; set; }
        public string durability { get; set; }
        public bool autodelete { get; set; }
        public string messagettl { get; set; }
        public string autoexpire { get; set; }
        public string maxlength { get; set; }
        public string deadletterex { get; set; }
        public string deadletterrt { get; set; }
        public string arguments { get; set; }
      }
    }

    public class Production
    {
      public Globalconfig globalconfig { get; set; }
      public Hostdetection hostdetection { get; set; }
      public DataSources datasources { get; set; }
      public Notifications notifications { get; set; }
      public Threatfeeds threatfeeds { get; set; }
    }

    public class Test
    {
      public Globalconfig globalconfig { get; set; }
      public Hostdetection hostdetection { get; set; }
      public DataSources datasources { get; set; }
      public Notifications notifications { get; set; }
      public Threatfeeds threatfeeds { get; set; }
    }

    public class PrimaryConfig
    {
      public bool runtest { get; set; }
      public string host { get; set; }
      public Globalconfig globalconfig { get; set; }
      public Hostdetection hostdetection { get; set; }
      public DataSources datasources { get; set; }
      public Notifications notifications { get; set; }
      public Threatfeeds threatfeeds { get; set; }
    }

    public class Que
    {
      public bool runtest { get; set; }
      public PrimaryConfig production { get; set; }
      public PrimaryConfig test { get; set; }
    }

    public class Key
    {
      public string _id { get; set; }
      public string _rev { get; set; }
      public Que queues { get; set; }
    }

    public class Row
    {
      public string id { get; set; }
      public Key key { get; set; }
      public object value { get; set; }
    }

    public class Queues
    {
      public int total_rows { get; set; }
      public int offset { get; set; }
      public List<Row> rows { get; set; }
    }
  }

}
