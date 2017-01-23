using System;
using System.IO;
using System.Xml;
using System.Xml.Serialization;

namespace FIDO_Detector.Fido_Support.XMLHelper
{
  internal static class ParseHelpers
  {
    //private static JavaScriptSerializer json;
    //private static JavaScriptSerializer JSON { get { return json ?? (json = new JavaScriptSerializer()); } }

    private static Stream ToStream(this string @this)
    {
      var stream = new MemoryStream();
      var writer = new StreamWriter(stream);
      writer.Write(@this);
      writer.Flush();
      stream.Position = 0;
      return stream;
    }

    public static T ParseXML<T>(this string @this) where T : class
    {

      try
      {
        var reader = XmlReader.Create(@this.Trim().ToStream(), new XmlReaderSettings() { ConformanceLevel = ConformanceLevel.Document });
        return new XmlSerializer(typeof(T)).Deserialize(reader) as T;
      }
      catch (Exception e)
      {
        Console.WriteLine(e.GetBaseException());
      }
      return null;
    }
  }
}
