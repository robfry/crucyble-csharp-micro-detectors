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

using System.Collections.Generic;
using Fido_Main.Fido_Support.Objects.Fido;

namespace Fido_Main.Notification.Notification_Helper
{
  public class Notification_Location_Helper
  {
    public static Dictionary<string, string> LocationReplacements(FidoReturnValues lFidoReturnValues, Dictionary<string, string> replacements)
    {
      if (lFidoReturnValues.Location == null)
      {
        replacements.Add("%asninfo%", "Location and ASN unknown");
        replacements.Add("%city%", string.Empty);
        replacements.Add("%country%", string.Empty);
        replacements.Add("%region%", string.Empty);
        return replacements;
      }
      if (lFidoReturnValues.Location != null)
      {
        if (lFidoReturnValues.Location.city != null)
        {
          replacements.Add("%city%", lFidoReturnValues.Location.city);
        }
        else
        {
          replacements.Add("%city%", string.Empty);
        }
        if (lFidoReturnValues.Location.country_name != null)
        {
          replacements.Add("%country%", lFidoReturnValues.Location.country_name);
        }
        else
        {
          replacements.Add("%country%", string.Empty);
        }
        if (lFidoReturnValues.Location.region_name != null)
        {
          replacements.Add("%region%", lFidoReturnValues.Location.region_name);
        }
        else
        {
          replacements.Add("%region%", string.Empty);
        }
        if (lFidoReturnValues.Location.pin != null)
        {
          replacements.Add("%asninfo%", lFidoReturnValues.Location.pin.location);
        }
        else
        {
          replacements.Add("%asninfo%", string.Empty);
        }
      }
      return replacements;
    }
 
  }
}