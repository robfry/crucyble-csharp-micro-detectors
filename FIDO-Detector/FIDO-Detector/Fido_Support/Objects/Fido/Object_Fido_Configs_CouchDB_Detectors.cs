using System.Collections.Generic;

namespace FIDO_Detector.Fido_Support.Objects.Fido
{
  public class Object_Fido_Configs_CouchDB_Detectors
  {
    public class Sensor
    {
      public string server { get; set; }
      public string token { get; set; }
      public List<string> query { get; set; }
      public string timer { get; set; }
    }

    public class Value
    {
      public string _id { get; set; }
      public string _rev { get; set; }
      public object type { get; set; }
      public string label { get; set; }
      public string detector { get; set; }
      public int detector_type { get; set; }
      public string vendor { get; set; }
      public string location { get; set; }
      public Sensor sensor { get; set; }
    }

    public class Row
    {
      public string id { get; set; }
      public string key { get; set; }
      public Value value { get; set; }
    }

    public class Detector
    {
      public int total_rows { get; set; }
      public int offset { get; set; }
      public List<Row> rows { get; set; }
    }
  
  }
}
