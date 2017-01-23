// /*
// *
// *  Copyright 2016  Netflix, Inc.
// *
// *     Licensed under the Apache License, Version 2.0 (the "License");
// *     you may not use this file except in compliance with the License.
// *     You may obtain a copy of the License at
// *
// *         http://www.apache.org/licenses/LICENSE-2.0
// *
// *     Unless required by applicable law or agreed to in writing, software
// *     distributed under the License is distributed on an "AS IS" BASIS,
// *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// *     See the License for the specific language governing permissions and
// *     limitations under the License.
// *
// */

using System;
using System.IO;
using System.Runtime.Serialization.Json;
using System.Text;
using FIDO_Detector.Fido_Support.ErrorHandling;

namespace FIDO_Detector
{
  public class SerializeJson
  {
    public static string Serialize<T>(T lFidoReturnValues)
    {
      try
      {
        var mStream = new MemoryStream();
        var serializer = new DataContractJsonSerializer(typeof(T));
        //var settings = new DataContractJsonSerializerSettings();
        serializer.WriteObject(mStream, lFidoReturnValues);
        var jsonString = Encoding.UTF8.GetString(mStream.ToArray());
        mStream.Close();
        return jsonString;

      }
      catch (Exception e)
      {
        Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in Json serialization area:" + e);
      }
      return string.Empty;
    }
  }
}