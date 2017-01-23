/*
 *
 *  Copyright 2015 Netflix, Inc.
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */

using System;
using System.Collections.Generic;
using System.Linq;
using Fido_Main.Director.Threat_Feeds;
using Fido_Main.Fido_Support.ErrorHandling;
using Fido_Main.Fido_Support.FidoDB;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Fido_Support.Objects.VirusTotal;
using VirusTotalNET.Objects;

namespace Fido_Main.Director.Scoring
{
  static class Matrix_Scoring
  {
    public static FidoReturnValues GetDetectorsScore(FidoReturnValues lFidoReturnValues)
    {
      //This section will iterate through each detector and then score each threatfeed.
      //todo: refractor each threatfeed so it's not done inside this area.

      var sDetector = lFidoReturnValues.CurrentDetector;

      switch (sDetector)
      {
        case "antivirus":
          if (lFidoReturnValues.CurrentDetector == "antivirus")
          {
            Console.WriteLine(@"Scoring AV detector information.");
            lFidoReturnValues.ThreatScore += AntiVirusScore(lFidoReturnValues);
          }
          break;

        case "bit9":
          if ((lFidoReturnValues.Bit9 != null) && (lFidoReturnValues.Bit9.VTReport != null) &&
              (lFidoReturnValues.CurrentDetector == "bit9"))
          {
            Console.WriteLine(@"Scoring Bit9 detector information.");
            var iBit9PositiveReturns = BitTotalPosReturn(lFidoReturnValues.Bit9.VTReport);
            if ((iBit9PositiveReturns[0] > 0) || (iBit9PositiveReturns[1] > 0))
            {
              lFidoReturnValues.ThreatScore += VirusTotalScore(iBit9PositiveReturns, true);
            }
          }
          break;

        case "ids":
          break;

        case "mas":
          break;

        case "mps":

          //score VirusTotal hash
          lFidoReturnValues.ThreatScore += GetMpsVTHashThreatScore(lFidoReturnValues);

          //score VirusTotal URL
          if ((lFidoReturnValues.FireEye.VirusTotal != null) &&
              (lFidoReturnValues.FireEye.VirusTotal.URLReturn != null) &&
              (lFidoReturnValues.FireEye.VirusTotal.URLReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring FireEye/VirusTotal detector URL information.");
            var iVTPositiveUrlReturns = VirusTotalPosReturnURL(lFidoReturnValues.FireEye.VirusTotal);
            if ((iVTPositiveUrlReturns[0] > 0) || (iVTPositiveUrlReturns[1] > 0))
            {
              lFidoReturnValues.ThreatScore += VirusTotalScore(iVTPositiveUrlReturns, false);
            }
          }

          //score VirusTotal IP
          if ((lFidoReturnValues.FireEye.VirusTotal != null) &&
              (lFidoReturnValues.FireEye.VirusTotal.IPReturn != null) &&
              (lFidoReturnValues.FireEye.VirusTotal.IPReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Cyphort/VirusTotal detector IP information.");
            var iVTPositiveIPReturns = VirusTotalPosIPReturn(lFidoReturnValues.FireEye.VirusTotal);
            if ((iVTPositiveIPReturns[0] > 0) || (iVTPositiveIPReturns[1] > 0) || (iVTPositiveIPReturns[2] > 0))
            {
              lFidoReturnValues.ThreatScore += VirusTotalIPScore(iVTPositiveIPReturns);
            }
          }

          //score Alienvault threat feed
          if ((lFidoReturnValues.FireEye.AlienVault != null) &&
              (lFidoReturnValues.FireEye.AlienVault.Activity != null))
          {
            Console.WriteLine(@"Scoring FireEye/AlienVault IP information.");
            lFidoReturnValues.ThreatScore += AlienVaultScore(lFidoReturnValues.FireEye.AlienVault);
          }
          break;

        case "cyphortv2":
          //score VirusTotal hash
          if ((lFidoReturnValues.Cyphort.VirusTotal != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.MD5HashReturn != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.MD5HashReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Cyphort/VirusTotal detector hash information.");
            var iVTPositiveHashReturns = VirusTotalPosReturnHash(lFidoReturnValues.Cyphort.VirusTotal);
            if ((iVTPositiveHashReturns[0] > 0) || (iVTPositiveHashReturns[1] > 0))
            {
              lFidoReturnValues.ThreatScore += VirusTotalScore(iVTPositiveHashReturns, true);
            }
          }

          //score VirusTotal URL
          if ((lFidoReturnValues.Cyphort.VirusTotal != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.URLReturn != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.URLReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Cyphort/VirusTotal detector URL information.");
            var iVTPositiveUrlReturns = VirusTotalPosReturnURL(lFidoReturnValues.Cyphort.VirusTotal);
            if ((iVTPositiveUrlReturns[0] > 0) || (iVTPositiveUrlReturns[1] > 0))
            {
              lFidoReturnValues.ThreatScore += VirusTotalScore(iVTPositiveUrlReturns, false);
            }
          }

          //score VirusTotal IP
          if ((lFidoReturnValues.Cyphort.VirusTotal != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.IPReturn != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.IPReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Cyphort/VirusTotal detector IP information.");
            var iVTPositiveIPReturns = VirusTotalPosIPReturn(lFidoReturnValues.Cyphort.VirusTotal);
            if ((iVTPositiveIPReturns[0] > 0) || (iVTPositiveIPReturns[1] > 0) || (iVTPositiveIPReturns[2] > 0))
            {
              lFidoReturnValues.ThreatScore += VirusTotalIPScore(iVTPositiveIPReturns);
            }
          }

          //score Alienvault threat feed
          if ((lFidoReturnValues.Cyphort.AlienVault != null) &&
              (lFidoReturnValues.Cyphort.AlienVault.Activity != null))
          {
            Console.WriteLine(@"Scoring Cyphort/AlienVault detector IP information.");
            lFidoReturnValues.ThreatScore += AlienVaultScore(lFidoReturnValues.Cyphort.AlienVault);
          }
          break;

        case "cyphort":
          //score VirusTotal hash
          if ((lFidoReturnValues.Cyphort.VirusTotal != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.MD5HashReturn != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.MD5HashReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Cyphort/VirusTotal detector hash information.");
            var iVTPositiveHashReturns = VirusTotalPosReturnHash(lFidoReturnValues.Cyphort.VirusTotal);
            if ((iVTPositiveHashReturns[0] > 0) || (iVTPositiveHashReturns[1] > 0))
            {
              lFidoReturnValues.Cyphort.VirusTotal.VirusTotalScore += Math.Round(VirusTotalScore(iVTPositiveHashReturns, true))/10;
              lFidoReturnValues.ThreatScore += VirusTotalScore(iVTPositiveHashReturns, true);
            }
          }

          //score VirusTotal URL
          if ((lFidoReturnValues.Cyphort.VirusTotal != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.URLReturn != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.URLReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Cyphort/VirusTotal detector URL information.");
            var iVTPositiveUrlReturns = VirusTotalPosReturnURL(lFidoReturnValues.Cyphort.VirusTotal);
            if ((iVTPositiveUrlReturns[0] > 0) || (iVTPositiveUrlReturns[1] > 0))
            {
              lFidoReturnValues.Cyphort.VirusTotal.VirusTotalScore += Math.Round(VirusTotalScore(iVTPositiveUrlReturns, false))/10;
              lFidoReturnValues.ThreatScore += VirusTotalScore(iVTPositiveUrlReturns, false);
            }
          }

          //score VirusTotal IP
          if ((lFidoReturnValues.Cyphort.VirusTotal != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.IPReturn != null) &&
              (lFidoReturnValues.Cyphort.VirusTotal.IPReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Cyphort/VirusTotal detector IP information.");
            var iVTPositiveIPReturns = VirusTotalPosIPReturn(lFidoReturnValues.Cyphort.VirusTotal);
            if ((iVTPositiveIPReturns[0] > 0) || (iVTPositiveIPReturns[1] > 0) || (iVTPositiveIPReturns[2] > 0))
            {
              lFidoReturnValues.Cyphort.VirusTotal.VirusTotalScore += Math.Round(VirusTotalIPScore(iVTPositiveIPReturns))/10;
              lFidoReturnValues.ThreatScore += VirusTotalIPScore(iVTPositiveIPReturns);
            }
          }

          //score ThreatGRID IP
          if ((lFidoReturnValues.Cyphort.ThreatGRID != null) && (lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Count > 0))
          {
            Console.WriteLine(@"Artifacts found in ThreatGRID IP data, downloading report.");

            if (lFidoReturnValues.Cyphort.ThreatGRID.IPSearch.Any())
            {
              Feeds_ThreatGRID.ReportHTML(lFidoReturnValues.Cyphort.ThreatGRID.IPSearch[0].Data.Items[0].HashID);
            }

            Console.WriteLine(@"Scoring Cyphort/ThreatGRID detector IP information.");

            var aggregateScore = lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Score);
            lFidoReturnValues.Cyphort.ThreatGRID.ThreatScore = aggregateScore/lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Count();

            var aggregateIndicators = lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Count);
            lFidoReturnValues.Cyphort.ThreatGRID.ThreatIndicators = aggregateIndicators / lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Count();

            var aggregateConfidence = lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxConfidence);
            lFidoReturnValues.Cyphort.ThreatGRID.ThreatConfidence = aggregateConfidence / lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Count();
            
            var aggregateSeverity = lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxSeverity);
            lFidoReturnValues.Cyphort.ThreatGRID.ThreatSeverity = aggregateSeverity / lFidoReturnValues.Cyphort.ThreatGRID.IPThreatInfo.Count();

            var fidoDB = new SqLiteDB().ExecuteScalar(@"select feed_weight from configs_threatfeed_threatgrid_scoring");
            
            lFidoReturnValues.ThreatScore += (lFidoReturnValues.Cyphort.ThreatGRID.ThreatScore * 10) / Convert.ToDouble(fidoDB);

          }

          if ((lFidoReturnValues.Cyphort.ThreatGRID != null) && (lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo != null) && (lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Count > 0))
          {
            Console.WriteLine(@"Artifacts found in ThreatGRID hash data, downloading report.");

            if (lFidoReturnValues.Cyphort.ThreatGRID.HashSearch.Any())
            {
              Feeds_ThreatGRID.ReportHTML(lFidoReturnValues.Cyphort.ThreatGRID.HashSearch[0].Data.Items[0].HashID);
            }

            Console.WriteLine(@"Scoring Cyphort/ThreatGRID detector hash information.");

            try
            {
              //Put this in a try statement because HashThreatInfo was erring, but not the other aggregates (???).
              var fubar = lFidoReturnValues.Cyphort.ThreatGRID;
              if (fubar.HashThreatInfo != null)
              {
                var aggScore = fubar.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Score);
                //lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Score);
                lFidoReturnValues.Cyphort.ThreatGRID.ThreatScore = aggScore/lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Count();
              }
              var aggregateScore = lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => (current + threatinfo.Data_Array.Score));
              lFidoReturnValues.Cyphort.ThreatGRID.ThreatScore = aggregateScore / lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Count();

              var aggregateIndicators = lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Count);
              lFidoReturnValues.Cyphort.ThreatGRID.ThreatIndicators = aggregateIndicators / lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Count();

              var aggregateConfidence = lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxConfidence);
              lFidoReturnValues.Cyphort.ThreatGRID.ThreatConfidence = aggregateConfidence / lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Count();

              var aggregateSeverity = lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxSeverity);
              lFidoReturnValues.Cyphort.ThreatGRID.ThreatSeverity = aggregateSeverity / lFidoReturnValues.Cyphort.ThreatGRID.HashThreatInfo.Count();
            }
            catch (Exception e)
            {
              Fido_EventHandler.SendEmail("Fido Error", "Fido Failed: {0} Exception caught in cyphort ThreatGrid fubar area:" + e);
            }

            var fidoDB = new SqLiteDB().ExecuteScalar(@"select feed_weight from configs_threatfeed_threatgrid_scoring");
            lFidoReturnValues.ThreatScore += (lFidoReturnValues.Cyphort.ThreatGRID.ThreatScore * 10) / Convert.ToDouble(fidoDB);

          } 

          //score Alienvault threat feed
          if ((lFidoReturnValues.Cyphort.AlienVault != null) && (lFidoReturnValues.Cyphort.AlienVault.Activity != null))
          {
            Console.WriteLine(@"Scoring Cyphort/AlienVault detector IP information.");
            lFidoReturnValues.ThreatScore += AlienVaultScore(lFidoReturnValues.Cyphort.AlienVault);
          }
          break;

        case "protectwise":
          //score VirusTotal hash
          if ((lFidoReturnValues.ProtectWise.VirusTotal != null) &&
              (lFidoReturnValues.ProtectWise.VirusTotal.MD5HashReturn != null) &&
              (lFidoReturnValues.ProtectWise.VirusTotal.MD5HashReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring ProtectWise/VirusTotal detector hash information.");
            var iVTPositiveHashReturns = VirusTotalPosReturnHash(lFidoReturnValues.ProtectWise.VirusTotal);
            if ((iVTPositiveHashReturns[0] > 0) || (iVTPositiveHashReturns[1] > 0))
            {
              lFidoReturnValues.ProtectWise.VirusTotal.VirusTotalScore += Math.Round(VirusTotalScore(iVTPositiveHashReturns, true)) / 10;
              lFidoReturnValues.ThreatScore += VirusTotalScore(iVTPositiveHashReturns, true);
            }
          }

          //score VirusTotal URL
          if ((lFidoReturnValues.ProtectWise.VirusTotal != null) &&
              (lFidoReturnValues.ProtectWise.VirusTotal.URLReturn != null) &&
              (lFidoReturnValues.ProtectWise.VirusTotal.URLReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring ProtectWise/VirusTotal detector URL information.");
            var iVTPositiveUrlReturns = VirusTotalPosReturnURL(lFidoReturnValues.ProtectWise.VirusTotal);
            if ((iVTPositiveUrlReturns[0] > 0) || (iVTPositiveUrlReturns[1] > 0))
            {
              lFidoReturnValues.ProtectWise.VirusTotal.VirusTotalScore += Math.Round(VirusTotalScore(iVTPositiveUrlReturns, false)) / 10;
              lFidoReturnValues.ThreatScore += VirusTotalScore(iVTPositiveUrlReturns, false);
            }
          }

          //score VirusTotal IP
          if ((lFidoReturnValues.ProtectWise.VirusTotal != null) &&
              (lFidoReturnValues.ProtectWise.VirusTotal.IPReturn != null) &&
              (lFidoReturnValues.ProtectWise.VirusTotal.IPReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring ProtectWise/VirusTotal detector IP information.");
            var iVTPositiveIPReturns = VirusTotalPosIPReturn(lFidoReturnValues.ProtectWise.VirusTotal);
            if ((iVTPositiveIPReturns[0] > 0) || (iVTPositiveIPReturns[1] > 0) || (iVTPositiveIPReturns[2] > 0))
            {
              lFidoReturnValues.ProtectWise.VirusTotal.VirusTotalScore += Math.Round(VirusTotalIPScore(iVTPositiveIPReturns)) / 10;
              lFidoReturnValues.ThreatScore += VirusTotalIPScore(iVTPositiveIPReturns);
            }
          }

          //score ThreatGRID IP
          if ((lFidoReturnValues.ProtectWise.ThreatGRID != null) && (lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Count > 0))
          {
            Console.WriteLine(@"Artifacts found in ThreatGRID IP data, downloading report.");

            if (lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch.Any())
            {
              //Feeds_ThreatGRID.ReportHTML(lFidoReturnValues.ProtectWise.ThreatGRID.IPSearch[0].Data.Items[0].HashID);
            }

            Console.WriteLine(@"Scoring ProtectWise/ThreatGRID detector IP information.");

            var aggregateScore = lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Score);
            lFidoReturnValues.ProtectWise.ThreatGRID.ThreatScore = aggregateScore / lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Count();

            var aggregateIndicators = lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Count);
            lFidoReturnValues.ProtectWise.ThreatGRID.ThreatIndicators = aggregateIndicators / lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Count();

            var aggregateConfidence = lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxConfidence);
            lFidoReturnValues.ProtectWise.ThreatGRID.ThreatConfidence = aggregateConfidence / lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Count();

            var aggregateSeverity = lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxSeverity);
            lFidoReturnValues.ProtectWise.ThreatGRID.ThreatSeverity = aggregateSeverity / lFidoReturnValues.ProtectWise.ThreatGRID.IPThreatInfo.Count();

            var fidoDB = new SqLiteDB().ExecuteScalar(@"select feed_weight from configs_threatfeed_threatgrid_scoring");

            lFidoReturnValues.ThreatScore += (lFidoReturnValues.ProtectWise.ThreatGRID.ThreatScore * 10) / Convert.ToDouble(fidoDB);

          }

          if ((lFidoReturnValues.ProtectWise.ThreatGRID != null) && (lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo != null) && (lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Count > 0))
          {
            Console.WriteLine(@"Artifacts found in ThreatGRID hash data, downloading report.");

            if (lFidoReturnValues.ProtectWise.ThreatGRID.HashSearch.Any())
            {
              Feeds_ThreatGRID.ReportHTML(lFidoReturnValues.ProtectWise.ThreatGRID.HashSearch[0].Data.Items[0].HashID);
            }

            Console.WriteLine(@"Scoring ProtectWise/ThreatGRID detector IP information.");

            var aggregateScore = lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Score);
            lFidoReturnValues.ProtectWise.ThreatGRID.ThreatScore = aggregateScore / lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Count();

            var aggregateIndicators = lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Count);
            lFidoReturnValues.ProtectWise.ThreatGRID.ThreatIndicators = aggregateIndicators / lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Count();

            var aggregateConfidence = lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxConfidence);
            lFidoReturnValues.ProtectWise.ThreatGRID.ThreatConfidence = aggregateConfidence / lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Count();

            var aggregateSeverity = lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxSeverity);
            lFidoReturnValues.ProtectWise.ThreatGRID.ThreatSeverity = aggregateSeverity / lFidoReturnValues.ProtectWise.ThreatGRID.HashThreatInfo.Count();

            var fidoDB = new SqLiteDB().ExecuteScalar(@"select feed_weight from configs_threatfeed_threatgrid_scoring");

            lFidoReturnValues.ThreatScore += (lFidoReturnValues.ProtectWise.ThreatGRID.ThreatScore * 10) / Convert.ToDouble(fidoDB);

          }

          //score Alienvault threat feed
          if ((lFidoReturnValues.ProtectWise.AlienVault != null) && (lFidoReturnValues.ProtectWise.AlienVault.Activity != null))
          {
            Console.WriteLine(@"Scoring ProtectWise/AlienVault detector IP information.");
            lFidoReturnValues.ThreatScore += AlienVaultScore(lFidoReturnValues.ProtectWise.AlienVault);
          }
          break;

        case "niddel":

        //score VirusTotal URL
          if ((lFidoReturnValues.Niddel.VirusTotal != null) &&
              (lFidoReturnValues.Niddel.VirusTotal.URLReturn != null) &&
              (lFidoReturnValues.Niddel.VirusTotal.URLReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Niddel/VirusTotal detector URL information.");
            var iVTPositiveUrlReturns = VirusTotalPosReturnURL(lFidoReturnValues.Niddel.VirusTotal);
            if ((iVTPositiveUrlReturns[0] > 0) || (iVTPositiveUrlReturns[1] > 0))
            {
              lFidoReturnValues.Niddel.VirusTotal.VirusTotalScore += Math.Round(VirusTotalScore(iVTPositiveUrlReturns, false)) / 10;
              lFidoReturnValues.ThreatScore += VirusTotalScore(iVTPositiveUrlReturns, false);
            }
          }

          //score VirusTotal IP
          if ((lFidoReturnValues.Niddel.VirusTotal != null) &&
              (lFidoReturnValues.Niddel.VirusTotal.IPReturn != null) &&
              (lFidoReturnValues.Niddel.VirusTotal.IPReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Niddel/VirusTotal detector IP information.");
            var iVTPositiveIPReturns = VirusTotalPosIPReturn(lFidoReturnValues.Niddel.VirusTotal);
            if ((iVTPositiveIPReturns[0] > 0) || (iVTPositiveIPReturns[1] > 0) || (iVTPositiveIPReturns[2] > 0))
            {
              lFidoReturnValues.Niddel.VirusTotal.VirusTotalScore += Math.Round(VirusTotalIPScore(iVTPositiveIPReturns)) / 10;
              lFidoReturnValues.ThreatScore += VirusTotalIPScore(iVTPositiveIPReturns);
            }
          }

          //score ThreatGRID IP
          if ((lFidoReturnValues.Niddel.ThreatGRID != null) && (lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo.Count > 0))
          {
            Console.WriteLine(@"Artifacts found in ThreatGRID IP data, downloading report.");

            if (lFidoReturnValues.Niddel.ThreatGRID.IPSearch.Any())
            {
              Feeds_ThreatGRID.ReportHTML(lFidoReturnValues.Niddel.ThreatGRID.IPSearch[0].Data.Items[0].HashID);
            }

            Console.WriteLine(@"Scoring Niddel/ThreatGRID detector IP information.");

            var aggregateScore = lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Score);
            lFidoReturnValues.Niddel.ThreatGRID.ThreatScore = aggregateScore / lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo.Count();

            var aggregateIndicators = lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Count);
            lFidoReturnValues.Niddel.ThreatGRID.ThreatIndicators = aggregateIndicators / lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo.Count();

            var aggregateConfidence = lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxConfidence);
            lFidoReturnValues.Niddel.ThreatGRID.ThreatConfidence = aggregateConfidence / lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo.Count();

            var aggregateSeverity = lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxSeverity);
            lFidoReturnValues.Niddel.ThreatGRID.ThreatSeverity = aggregateSeverity / lFidoReturnValues.Niddel.ThreatGRID.IPThreatInfo.Count();

            var fidoDB = new SqLiteDB().ExecuteScalar(@"select feed_weight from configs_threatfeed_threatgrid_scoring");

            lFidoReturnValues.ThreatScore += (lFidoReturnValues.Niddel.ThreatGRID.ThreatScore * 10) / Convert.ToDouble(fidoDB);

          }
          break;

        case "carbonblack":
          //score VirusTotal hash
          if ((lFidoReturnValues.CB.Alert.VirusTotal != null) &&
              (lFidoReturnValues.CB.Alert.VirusTotal.MD5HashReturn != null) &&
              (lFidoReturnValues.CB.Alert.VirusTotal.MD5HashReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Carbon Black/VirusTotal detector hash information.");
            var iVTPositiveHashReturns = VirusTotalPosReturnHash(lFidoReturnValues.CB.Alert.VirusTotal);
            if ((iVTPositiveHashReturns[0] > 0) || (iVTPositiveHashReturns[1] > 0))
            {
              double intReturn = VirusTotalScore(iVTPositiveHashReturns, true);
              lFidoReturnValues.CB.Alert.VirusTotal.VirusTotalScore += Math.Round(intReturn) / 10;
              lFidoReturnValues.ThreatScore += intReturn;
            }
          }

          if ((lFidoReturnValues.CB.Alert.ThreatGRID != null) && (lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo != null) && (lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Count > 0))
          {
            Console.WriteLine(@"Artifacts found in ThreatGRID hash data, downloading report.");

            if (lFidoReturnValues.CB.Alert.ThreatGRID.HashSearch.Any())
            {
              Feeds_ThreatGRID.ReportHTML(lFidoReturnValues.CB.Alert.ThreatGRID.HashSearch[0].Data.Items[0].HashID);
            }

            Console.WriteLine(@"Scoring Carbon Black/ThreatGRID detector IP information.");

            var aggregateScore = lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Score);
            lFidoReturnValues.CB.Alert.ThreatGRID.ThreatScore = aggregateScore / lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Count();

            var aggregateIndicators = lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Count);
            lFidoReturnValues.CB.Alert.ThreatGRID.ThreatIndicators = aggregateIndicators / lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Count();

            var aggregateConfidence = lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxConfidence);
            lFidoReturnValues.CB.Alert.ThreatGRID.ThreatConfidence = aggregateConfidence / lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Count();

            var aggregateSeverity = lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxSeverity);
            lFidoReturnValues.CB.Alert.ThreatGRID.ThreatSeverity = aggregateSeverity / lFidoReturnValues.CB.Alert.ThreatGRID.HashThreatInfo.Count();

            //todo: move this SQL to the DB
            var fidoDB = new SqLiteDB().ExecuteScalar(@"select feed_weight from configs_threatfeed_threatgrid_scoring");

            lFidoReturnValues.ThreatScore += (lFidoReturnValues.CB.Alert.ThreatGRID.ThreatScore * 10) / Convert.ToDouble(fidoDB);

          }

          //score Alienvault threat feed
          if ((lFidoReturnValues.CB.Alert.AlienVault != null) && (lFidoReturnValues.CB.Alert.AlienVault.Activity != null))
          {
            Console.WriteLine(@"Scoring Carbon Black/AlienVault detector IP information.");
            lFidoReturnValues.ThreatScore += AlienVaultScore(lFidoReturnValues.CB.Alert.AlienVault);
          }
          break;

        case "sentinelone":
          //score VirusTotal hash
          if ((lFidoReturnValues.SentinelOne.VirusTotal != null) &&
              (lFidoReturnValues.SentinelOne.VirusTotal.MD5HashReturn != null) &&
              (lFidoReturnValues.SentinelOne.VirusTotal.MD5HashReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring Carbon Black/VirusTotal detector hash information.");
            var iVTPositiveHashReturns = VirusTotalPosReturnHash(lFidoReturnValues.SentinelOne.VirusTotal);
            if ((iVTPositiveHashReturns[0] > 0) || (iVTPositiveHashReturns[1] > 0))
            {
              double intReturn = VirusTotalScore(iVTPositiveHashReturns, true);
              lFidoReturnValues.SentinelOne.VirusTotal.VirusTotalScore += Math.Round(intReturn) / 10;
              lFidoReturnValues.ThreatScore += intReturn;
            }
          }

          if ((lFidoReturnValues.SentinelOne.ThreatGRID != null) && (lFidoReturnValues.SentinelOne.ThreatGRID.HashThreatInfo != null) && (lFidoReturnValues.SentinelOne.ThreatGRID.HashThreatInfo.Count > 0))
          {
            Console.WriteLine(@"Artifacts found in ThreatGRID hash data, downloading report.");

            if (lFidoReturnValues.SentinelOne.ThreatGRID.HashSearch.Any())
            {
              Feeds_ThreatGRID.ReportHTML(lFidoReturnValues.SentinelOne.ThreatGRID.HashSearch[0].Data.Items[0].HashID);
            }

            Console.WriteLine(@"Scoring Carbon Black/ThreatGRID detector IP information.");

            var aggregateScore = lFidoReturnValues.SentinelOne.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Score);
            lFidoReturnValues.SentinelOne.ThreatGRID.ThreatScore = aggregateScore / lFidoReturnValues.SentinelOne.ThreatGRID.HashThreatInfo.Count();

            var aggregateIndicators = lFidoReturnValues.SentinelOne.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Count);
            lFidoReturnValues.SentinelOne.ThreatGRID.ThreatIndicators = aggregateIndicators / lFidoReturnValues.SentinelOne.ThreatGRID.HashThreatInfo.Count();

            var aggregateConfidence = lFidoReturnValues.SentinelOne.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxConfidence);
            lFidoReturnValues.SentinelOne.ThreatGRID.ThreatConfidence = aggregateConfidence / lFidoReturnValues.SentinelOne.ThreatGRID.HashThreatInfo.Count();

            var aggregateSeverity = lFidoReturnValues.SentinelOne.ThreatGRID.HashThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxSeverity);
            lFidoReturnValues.SentinelOne.ThreatGRID.ThreatSeverity = aggregateSeverity / lFidoReturnValues.SentinelOne.ThreatGRID.HashThreatInfo.Count();

            //todo: move this SQL to the DB
            var fidoDB = new SqLiteDB().ExecuteScalar(@"select feed_weight from configs_threatfeed_threatgrid_scoring");

            lFidoReturnValues.ThreatScore += (lFidoReturnValues.SentinelOne.ThreatGRID.ThreatScore * 10) / Convert.ToDouble(fidoDB);

          }

          break;

        case "pan":

          //score VirusTotal URL
          //if ((lFidoReturnValues.PaloAlto.VirusTotal != null) &&
          //    (lFidoReturnValues.PaloAlto.VirusTotal.URLReturn != null) &&
          //    (lFidoReturnValues.PaloAlto.VirusTotal.URLReturn.Count > 0))
          //{
          //  Console.WriteLine(@"Scoring PaloAlto/VirusTotal detector URL information.");
          //  var iVTPositiveUrlReturns = VirusTotalPosReturn(lFidoReturnValues.PaloAlto.VirusTotal, false);
          //  if ((iVTPositiveUrlReturns[0] > 0) || (iVTPositiveUrlReturns[1] > 0))
          //  {
          //    lFidoReturnValues.PaloAlto.VirusTotal.VirusTotalScore += Math.Round(VirusTotalScore(iVTPositiveUrlReturns, false)) / 10;
          //    lFidoReturnValues.ThreatScore += VirusTotalScore(iVTPositiveUrlReturns, false);
          //  }
          //}

          //score VirusTotal IP
          if ((lFidoReturnValues.PaloAlto.VirusTotal != null) &&
              (lFidoReturnValues.PaloAlto.VirusTotal.IPReturn != null) &&
              (lFidoReturnValues.PaloAlto.VirusTotal.IPReturn.Count > 0))
          {
            Console.WriteLine(@"Scoring PaloAlto/VirusTotal detector IP information.");
            var iVTPositiveIPReturns = VirusTotalPosIPReturn(lFidoReturnValues.PaloAlto.VirusTotal);
            if ((iVTPositiveIPReturns[0] > 0) || (iVTPositiveIPReturns[1] > 0) || (iVTPositiveIPReturns[2] > 0))
            {
              lFidoReturnValues.PaloAlto.VirusTotal.VirusTotalScore += Math.Round(VirusTotalIPScore(iVTPositiveIPReturns)) / 10;
              lFidoReturnValues.ThreatScore += VirusTotalIPScore(iVTPositiveIPReturns);
            }
          }

          //score ThreatGRID IP
          if ((lFidoReturnValues.PaloAlto.ThreatGRID != null) && (lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo != null) && (lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Count > 0))
          {
            Console.WriteLine(@"Artifacts found in ThreatGRID IP data, downloading report.");

            if (lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch.Any())
            {
              Feeds_ThreatGRID.ReportHTML(lFidoReturnValues.PaloAlto.ThreatGRID.IPSearch[0].Data.Items[0].HashID);
            }

            Console.WriteLine(@"Scoring PaloAlto/ThreatGRID detector IP information.");

            var aggregateScore = lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Score);
            lFidoReturnValues.PaloAlto.ThreatGRID.ThreatScore = aggregateScore / lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Count();

            var aggregateIndicators = lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.Count);
            lFidoReturnValues.PaloAlto.ThreatGRID.ThreatIndicators = aggregateIndicators / lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Count();

            var aggregateConfidence = lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxConfidence);
            lFidoReturnValues.PaloAlto.ThreatGRID.ThreatConfidence = aggregateConfidence / lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Count();

            var aggregateSeverity = lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Aggregate(0, (current, threatinfo) => current + threatinfo.Data_Array.MaxSeverity);
            lFidoReturnValues.PaloAlto.ThreatGRID.ThreatSeverity = aggregateSeverity / lFidoReturnValues.PaloAlto.ThreatGRID.IPThreatInfo.Count();

            var fidoDB = new SqLiteDB().ExecuteScalar(@"select feed_weight from configs_threatfeed_threatgrid_scoring");

            lFidoReturnValues.ThreatScore += (lFidoReturnValues.PaloAlto.ThreatGRID.ThreatScore * 10) / Convert.ToDouble(fidoDB);

          }
          break;
      }

      return lFidoReturnValues;
    }

    private static double GetMpsVTHashThreatScore(FidoReturnValues lFidoReturnValues)
    {
      double iThreatScore = 0;
      if ((lFidoReturnValues.FireEye.VirusTotal == null) || (lFidoReturnValues.FireEye.VirusTotal.MD5HashReturn == null) || (lFidoReturnValues.FireEye.VirusTotal.MD5HashReturn.Count <= 0)) return iThreatScore;
      Console.WriteLine(@"Scoring FireEye/VirusTotal detector hash information.");
        
      var iVTPositiveHashReturns = VirusTotalPosReturnHash(lFidoReturnValues.FireEye.VirusTotal);
      if ((iVTPositiveHashReturns[0] > 0) || (iVTPositiveHashReturns[1] > 0))
      {
        iThreatScore += VirusTotalScore(iVTPositiveHashReturns, true);
      }
      return iThreatScore;
    }

    //private static int[] ThreatGRIDPosReturn(ThreatGRIDReturnValues threatGridReturnValues)
    //{

    //  return ;
    //}

    private static int[] BitTotalPosReturn(IList<FileReport> vtEntry)
    {
      var iPosReturns = 0;
      var iPostTrojReturns = 0;
        
      if (vtEntry[0].Positives > 0)
      {
        iPostTrojReturns +=
          (from t in vtEntry[0].Scans
            where t.Value.Result != null
            select t.Value.Result.ToLower()
            into sResult
            select sResult.Contains("troj")).Count(isTrojan => isTrojan);
        iPosReturns += vtEntry[0].Positives;
      }
      var iReturn = new[] { iPosReturns, iPostTrojReturns };
      return iReturn;
    }

    private static int[] VirusTotalPosReturnHash(VirusTotalReturnValues virusTotalReturnValues)
    {
      var iPosReturns = 0;
      var iPostTrojReturns = 0;
      var lVTReport = virusTotalReturnValues.MD5HashReturn;
      foreach (var vtEntry in lVTReport.Where(vtEntry => vtEntry.Positives > 0))
      {
        iPostTrojReturns += (from t in vtEntry.Scans
                             where t.Value.Result != null
                             select t.Value.Result.ToLower()
                               into sResult
                               let isTrojan = false
                               select sResult.Contains("troj")).Count(isTrojan => isTrojan);
        iPosReturns += vtEntry.Positives;
      }
      var iReturn = new[] { iPosReturns, iPostTrojReturns };
      return iReturn;
    }

    private static int[] VirusTotalPosReturnURL(VirusTotalReturnValues virusTotalReturnValues)
    {
      var iPosReturns = 0;
      var iPostTrojReturns = 0;
      var lVTReport = virusTotalReturnValues.URLReturn;
      foreach (var vtEntry in lVTReport.Where(vtEntry => vtEntry.Positives > 0))
      {
        iPostTrojReturns += (from t in vtEntry.Scans
                             where t.Value.Result != null
                             select t.Value.Result.ToLower()
                               into sResult
                               let isTrojan = false
                               select sResult.Contains("malicious site")).Count(isTrojan => isTrojan);
        iPosReturns += vtEntry.Positives;
      }
      var iReturn = new[] { iPosReturns, iPostTrojReturns };
      return iReturn;
    }

    private static List<double> VirusTotalPosIPReturn(VirusTotalReturnValues virusTotalReturnValues)
    {

      List<Object_VirusTotal_IP.IPReport> lVTReport = virusTotalReturnValues.IPReturn;
      double countDetectedUrls = 0;
      double countDetectedDownloads = 0;
      double countDetectedComms = 0;

      foreach (var vtEntry in lVTReport)
      {
        if (vtEntry.DetectedUrls != null && vtEntry.DetectedUrls.Any())
        {
          for (var i = 0; i < vtEntry.DetectedUrls.Count(); i++)
          {
            if (vtEntry.DetectedUrls[i].Positives != null & vtEntry.DetectedUrls[i].Positives > 0)
            {
              //todo: move the below integer values to database configuration
              if (vtEntry.DetectedUrls[i].Positives >= 10)
              {
                countDetectedUrls = countDetectedUrls + (vtEntry.DetectedUrls[i].Positives * 2);
              }
              else if ((vtEntry.DetectedUrls[i].Positives >= 5) && (vtEntry.DetectedUrls[i].Positives < 10))
              {
                countDetectedUrls = countDetectedUrls + (vtEntry.DetectedUrls[i].Positives * 1.35);
              }
              else if (vtEntry.DetectedUrls[i].Positives >= 3)
              {
                countDetectedUrls = countDetectedUrls + (vtEntry.DetectedUrls[i].Positives * .85);
              }
            }
          }
        }
        if (vtEntry.DetectedCommunicatingSamples != null && vtEntry.DetectedCommunicatingSamples.Any())
        {
          for (var i = 0; i < vtEntry.DetectedCommunicatingSamples.Count(); i++)
          {
            if (vtEntry.DetectedCommunicatingSamples[i].Positives != null & vtEntry.DetectedCommunicatingSamples[i].Positives >= 1)
            {
              if (vtEntry.DetectedCommunicatingSamples[i].Positives >= 10)
              {
                countDetectedComms = countDetectedComms + (vtEntry.DetectedCommunicatingSamples[i].Positives * .55);
              }
              else if ((vtEntry.DetectedCommunicatingSamples[i].Positives >= 5) && (vtEntry.DetectedCommunicatingSamples[i].Positives < 10))
              {
                countDetectedComms = countDetectedComms + (vtEntry.DetectedCommunicatingSamples[i].Positives * .35);
              }
              else if (vtEntry.DetectedCommunicatingSamples[i].Positives < 5)
              {
                countDetectedComms = countDetectedComms + (vtEntry.DetectedCommunicatingSamples[i].Positives * .25);
              }
            }
          }
        }
        if (vtEntry.DetectedDownloadedSamples != null && vtEntry.DetectedDownloadedSamples.Any())
        {
          for (var i = 0; i < vtEntry.DetectedDownloadedSamples.Count(); i++)
          {
            if (vtEntry.DetectedDownloadedSamples[i].Positives != null & vtEntry.DetectedDownloadedSamples[i].Positives >= 1)
            {
              if (vtEntry.DetectedDownloadedSamples[i].Positives >= 10)
              {
                countDetectedDownloads = countDetectedDownloads + (vtEntry.DetectedDownloadedSamples[i].Positives * 1.5);
              }
              else if ((vtEntry.DetectedDownloadedSamples[i].Positives < 10) && (vtEntry.DetectedDownloadedSamples[i].Positives >= 5))
              {
                countDetectedDownloads = countDetectedDownloads + (vtEntry.DetectedDownloadedSamples[i].Positives * 1.1);
              }
              else if (vtEntry.DetectedDownloadedSamples[i].Positives < 5)
              {
                countDetectedDownloads = countDetectedDownloads + (vtEntry.DetectedDownloadedSamples[i].Positives * .95);
              }
            }
          }
        }
      }

      var lReturn = new List<double> { countDetectedComms, countDetectedDownloads, countDetectedUrls };
      return lReturn;

    }

    private static double VirusTotalScore(IList<int> iVTPositiveReturns, bool isHash)
    {

      var iTrojanScore = Convert.ToInt16(new SqLiteDB().ExecuteScalarArray(@"select trojanscore from configs_threatfeed_virustotal_scoring"));
      var iTrojanWeight = Convert.ToInt16(new SqLiteDB().ExecuteScalarArray(@"select trojanweight from configs_threatfeed_virustotal_scoring"));
      var iRegularScore = Convert.ToInt16(new SqLiteDB().ExecuteScalarArray(@"select regularscore from configs_threatfeed_virustotal_scoring"));
      var iRegularWeight = Convert.ToInt16(new SqLiteDB().ExecuteScalarArray(@"select regularweight from configs_threatfeed_virustotal_scoring"));
      var iUrlRegularScore = Convert.ToInt16(new SqLiteDB().ExecuteScalarArray(@"select urlregularscore from configs_threatfeed_virustotal_scoring"));
      var iUrlRegularWeight = Convert.ToInt16(new SqLiteDB().ExecuteScalarArray(@"select urlregularweight from configs_threatfeed_virustotal_scoring"));
      double iTotalReturn = 0;

      if ((iVTPositiveReturns[1] >= iTrojanScore) & (isHash))
      {
        iTotalReturn = iTrojanWeight * iVTPositiveReturns[1];
      }
      if ((iVTPositiveReturns[1] >= iUrlRegularScore) & (!isHash))
      {
        iTotalReturn = iUrlRegularWeight * iVTPositiveReturns[1];
      }
      if ((iVTPositiveReturns[0] >= iRegularScore) & (isHash))
      {
        iTotalReturn = iRegularWeight * iVTPositiveReturns[0];
      }
      return iTotalReturn;
    }

    private static double VirusTotalIPScore(IList<double> iVTPositiveReturns)
    {

      var iDetectedDownload = Convert.ToDouble(new SqLiteDB().ExecuteScalarArray(@"select detecteddownloadscore from configs_threatfeed_virustotal_scoring"));
      var iDetectedDownloadWeight = Convert.ToDouble(new SqLiteDB().ExecuteScalarArray(@"select detecteddownloadweight from configs_threatfeed_virustotal_scoring"));
      var iDetectedDownloadMultiplier = Convert.ToDouble(new SqLiteDB().ExecuteScalarArray(@"select detecteddownloadmultiplier from configs_threatfeed_virustotal_scoring"));
      var iDetectedComm = Convert.ToDouble(new SqLiteDB().ExecuteScalarArray(@"select detectedcommScore from configs_threatfeed_virustotal_scoring"));
      var iDetectedCommWeight = Convert.ToDouble(new SqLiteDB().ExecuteScalarArray(@"select detectedcommweight from configs_threatfeed_virustotal_scoring"));
      var iDetectedCommMultiplier = Convert.ToDouble(new SqLiteDB().ExecuteScalarArray(@"select detectedcommmultiplier from configs_threatfeed_virustotal_scoring"));
      var iDetectedURLs = Convert.ToDouble(new SqLiteDB().ExecuteScalarArray(@"select detectedurlscore from configs_threatfeed_virustotal_scoring"));
      var iDetectedURLsWeight = Convert.ToDouble(new SqLiteDB().ExecuteScalarArray(@"select detectedurlweight from configs_threatfeed_virustotal_scoring"));
      var iDetectedURLMultiplier = Convert.ToDouble(new SqLiteDB().ExecuteScalarArray(@"select detectedurlmultiplier from configs_threatfeed_virustotal_scoring"));
      var iFeedWeight = Convert.ToDouble(new SqLiteDB().ExecuteScalarArray(@"select feedweight from configs_threatfeed_virustotal_scoring"));
      double iTotalReturn = 0;

      if (iVTPositiveReturns[1] >= iDetectedDownload)
      {
        iTotalReturn += (iDetectedDownloadWeight * iDetectedDownloadMultiplier) * iVTPositiveReturns[1];
      }
      if (iVTPositiveReturns[0] >= iDetectedComm)
      {
        iTotalReturn += (iDetectedCommWeight * iDetectedCommMultiplier) * iVTPositiveReturns[0];
      }
      if (iVTPositiveReturns[2] >= iDetectedURLs)
      {
        iTotalReturn += (iDetectedURLsWeight * iDetectedURLMultiplier) * iVTPositiveReturns[2];
      }

      iTotalReturn = iTotalReturn / iFeedWeight;
      return iTotalReturn;
    }

    public static FidoReturnValues GetHistoricalHashCount(FidoReturnValues lFidoReturnValues)
    {
      if (lFidoReturnValues.HistoricalEvent.HashCount >= lFidoReturnValues.HistoricalEvent.HashScore)
      {
        Console.WriteLine(@"Hash seen before and is above threshold, scoring historical information.");
        lFidoReturnValues.IsHashSeenBefore = true;
        if (lFidoReturnValues.HistoricalEvent.HashCount >= lFidoReturnValues.HistoricalEvent.HashIncrement)
        {
          lFidoReturnValues.ThreatScore += lFidoReturnValues.HistoricalEvent.HashWeight * lFidoReturnValues.HistoricalEvent.HashMultiplier;
        }
        else
        {
          lFidoReturnValues.ThreatScore += lFidoReturnValues.HistoricalEvent.HashWeight;
        }
      }
      return lFidoReturnValues;
    }

    public static FidoReturnValues GetHistoricalURLCount(FidoReturnValues lFidoReturnValues)
    {
      if (lFidoReturnValues.HistoricalEvent.UrlCount >= lFidoReturnValues.HistoricalEvent.UrlScore)
      {
        Console.WriteLine(@"URL seen before and is above threshold, scoring historical information.");
        lFidoReturnValues.IsUrlSeenBefore = true;
        if (lFidoReturnValues.HistoricalEvent.UrlCount >= lFidoReturnValues.HistoricalEvent.UrlIncrement)
        {
          lFidoReturnValues.ThreatScore += lFidoReturnValues.HistoricalEvent.UrlWeight * lFidoReturnValues.HistoricalEvent.UrlMultiplier;
        }
        else
        {
          lFidoReturnValues.ThreatScore += lFidoReturnValues.HistoricalEvent.UrlWeight;
        }
      }
      return lFidoReturnValues;
    }

    public static FidoReturnValues GetHistoricalIPCount(FidoReturnValues lFidoReturnValues)
    {
      if (lFidoReturnValues.HistoricalEvent.IpCount > lFidoReturnValues.HistoricalEvent.IpScore)
      {
        Console.WriteLine(@"IP address seen before and is above threshold, scoring historical information.");
        lFidoReturnValues.IsIPSeenBefore = true;
        if (lFidoReturnValues.HistoricalEvent.IpCount >= lFidoReturnValues.HistoricalEvent.IpIncrement)
        {
          lFidoReturnValues.ThreatScore += lFidoReturnValues.HistoricalEvent.IpWeight * lFidoReturnValues.HistoricalEvent.IpMultiplier;
        }
        else
        {
          lFidoReturnValues.ThreatScore += lFidoReturnValues.HistoricalEvent.IpWeight;
        }
      }
      return lFidoReturnValues;
    }

    public static int AlienVaultScore(AlienVaultReturnValues lAlienVaultReturnValues)
    {
      var lMalwareTypes = Object_Fido_Configs.GetAsString("fido.securityfeed.alienvault.malwarevalues", String.Empty).Split(',').ToList();
      var iRiskScoreHigh = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.riskscorehigh", 0);
      var iRiskScoreMedium = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.riskscoremedium", 0);
      var iRiskScoreLow = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.riskscorelow", 0);
      var iRiskWeightHigh = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.riskweighthigh", 0);
      var iRiskWeightMedium = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.riskweightmedium", 0);
      var iRiskWeightLow = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.riskweightlow", 0);
      var iReliabilityScoreHigh = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.reliabilityscorehigh", 0);
      var iReliabilityScoreMedium = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.reliabilityscoremedium", 0);
      var iReliabilityScoreLow = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.reliabilityscorelow", 0);
      var iReliabilityWeightHigh = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.reliabilityweighthigh", 0);
      var iReliabilityWeightMedium = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.reliabilityweightmedium", 0);
      var iReliabilityWeightLow = Object_Fido_Configs.GetAsInt("fido.securityfeed.alienvault.reliabilityweightlow", 0);
      var iScore = 0;

      foreach (var sNewType in lMalwareTypes.Select(sType => sType.ToLower() == "c and c" ? "c&c" : sType).Where(sNewType => String.Equals(sNewType, lAlienVaultReturnValues.Activity, StringComparison.CurrentCultureIgnoreCase)))
      {
        if (lAlienVaultReturnValues.Reliability > iReliabilityScoreHigh)
        {
          if (lAlienVaultReturnValues.Risk > iRiskScoreHigh)
          {
            iScore = iRiskWeightHigh * iReliabilityWeightHigh;
          }
          else if (lAlienVaultReturnValues.Risk > iRiskScoreMedium)
          {
            iScore = iRiskWeightMedium * iReliabilityWeightHigh;
          }
          else if (lAlienVaultReturnValues.Risk < iRiskScoreLow)
          {
            iScore = iRiskWeightLow * iReliabilityWeightHigh;
          }
        }
        else if (lAlienVaultReturnValues.Reliability > iReliabilityScoreMedium)
        {
          if (lAlienVaultReturnValues.Risk > iRiskScoreHigh)
          {
            iScore = iRiskWeightHigh * iReliabilityWeightMedium;
          }
          else if (lAlienVaultReturnValues.Risk > iRiskScoreMedium)
          {
            iScore = iRiskWeightMedium * iReliabilityWeightMedium;
          }
          else if (lAlienVaultReturnValues.Risk < iRiskScoreLow)
          {
            iScore = iRiskWeightLow * iReliabilityWeightMedium;
          }
        }
        else if (lAlienVaultReturnValues.Reliability < iReliabilityScoreLow)
        {
          if (lAlienVaultReturnValues.Risk > iRiskScoreHigh)
          {
            iScore = iRiskWeightHigh * iReliabilityWeightLow;
          }
          else if (lAlienVaultReturnValues.Risk > iRiskScoreMedium)
          {
            iScore = iRiskWeightMedium * iReliabilityWeightLow;
          }
          else if (lAlienVaultReturnValues.Risk < iRiskScoreLow)
          {
            iScore = iRiskWeightLow * iReliabilityWeightLow;
          }
        }
      }
      return iScore;
    }

    public static FidoReturnValues GetUserScore(FidoReturnValues lFidoReturnValues)
    {
      var sUserTitles = new SqLiteDB().ExecuteScalar(@"select titles from configs_posture_user");
      var sUserDepartment = new SqLiteDB().ExecuteScalar(@"select department from configs_posture_user");
      var sUserTitlesArray = sUserTitles.Split(',');
      var sUserDepartmentArray = sUserDepartment.Split(',');
      var sTitleScoreWeight = Convert.ToInt16(new SqLiteDB().ExecuteScalarArray(@"select titlesscoreweight from configs_posture_user"));
      var sDepartmentScoreWeight = Convert.ToInt16(new SqLiteDB().ExecuteScalarArray(@"select departmentscoreweight from configs_posture_user")); 

      //user title section
      if ((sUserTitlesArray.Any()) && (sUserTitlesArray[0] != String.Empty) &&
          (lFidoReturnValues.UserInfo.Title != null))
      {
        Console.WriteLine(@"Scoring user title information.");
        foreach (var sTitle in sUserTitlesArray.Where(sTitle => sTitle.ToLower() == lFidoReturnValues.UserInfo.Title.ToLower()))
        {
          lFidoReturnValues.UserScore += Convert.ToInt16(sTitleScoreWeight);
        }
      }

      //user department section
      if ((sUserDepartmentArray.Any()) && (sUserDepartmentArray[0] != String.Empty) && (lFidoReturnValues.UserInfo.Department != null))
      {
        Console.WriteLine(@"Scoring user department information.");
        foreach (var sDepartment in sUserDepartmentArray.Where(sDepartment => String.Equals(sDepartment, lFidoReturnValues.UserInfo.Department, StringComparison.CurrentCultureIgnoreCase)))
        {
          lFidoReturnValues.UserScore += Convert.ToInt16(sDepartmentScoreWeight);
        }
      }

      return lFidoReturnValues;
    }

    public static FidoReturnValues GetPatchScore(FidoReturnValues lFidoReturnValues)
    {
      if ((lFidoReturnValues.Inventory.Landesk != null) && (lFidoReturnValues.Inventory.Landesk.Patches != null))
      {
        Console.WriteLine(@"Scoring Windows physical system patch status.");
        var iCriticalPaches = Convert.ToInt16(new SqLiteDB().ExecuteScalarArray(@"select criticalpatches from configs_posture_machine"));
        var iCriticalPachesWeight = Convert.ToInt16(new SqLiteDB().ExecuteScalarArray(@"select criticalpatchesweight from configs_posture_machine"));
        var iHighPatches = Convert.ToInt16(new SqLiteDB().ExecuteScalarArray(@"select highpatches from configs_posture_machine"));
        var iHighPatchesWeight = Convert.ToInt16(new SqLiteDB().ExecuteScalarArray(@"select highpatchesweight from configs_posture_machine"));
        var iLowPatches = Convert.ToInt16(new SqLiteDB().ExecuteScalarArray(@"select lowpatches from configs_posture_machine"));
        var iLowPatchesWeight = Convert.ToInt16(new SqLiteDB().ExecuteScalarArray(@"select lowpatchesweight from configs_posture_machine"));
        var lPatches = lFidoReturnValues.Inventory.Landesk.Patches;
        var iCrit = lPatches[1];
        var iHigh = lPatches[2];
        var iLow = lPatches[3];

        if (iCrit >= iCriticalPaches)
        {
          lFidoReturnValues.MachineScore += iCriticalPachesWeight;
          lFidoReturnValues.IsPatch = true;
        }
        if (iHigh >= iHighPatches)
        {
          lFidoReturnValues.MachineScore += iHighPatchesWeight;
          lFidoReturnValues.IsPatch = true;
        }
        if (iLow >= iLowPatches)
        {
          lFidoReturnValues.MachineScore += iLowPatchesWeight;
        }
      }
      else if (lFidoReturnValues.Inventory.Jamf != null)
      {
        //todo: reserved to get jamf patch values
        Console.WriteLine(@"Scoring Mac physical system patch status.");
      }

      return lFidoReturnValues;
    }

    public static FidoReturnValues GetCBScore(FidoReturnValues lFidoReturnValues)
    {
      var cbNotInstalled = Convert.ToInt16(new SqLiteDB().ExecuteScalarArray(@"select avnotinstalled from configs_posture_machine"));
      var cbNotRunning = Convert.ToInt16(new SqLiteDB().ExecuteScalarArray(@"select avnotrunning from configs_posture_machine"));
      Console.WriteLine(@"Scoring detected security software stack status.");
      if (lFidoReturnValues.Inventory.Landesk != null)
      {
        if (lFidoReturnValues.Inventory.Landesk.CBVersion == null) lFidoReturnValues.MachineScore += cbNotInstalled;
        if (lFidoReturnValues.Inventory.Landesk.CBRunning == null) lFidoReturnValues.MachineScore += cbNotRunning;
        if (lFidoReturnValues.Inventory.Landesk.SentinelRunning == null) lFidoReturnValues.MachineScore += cbNotInstalled;
      }
      else if ((lFidoReturnValues.Inventory.Jamf != null))
      {
        //todo: reserved for getting AV Jamf values
      }

      //todo: not sure what I was doing here???
      //else if ((lFidoReturnValues.Hostname != null) && (lFidoReturnValues.Hostname != "unknown") && (lFidoReturnValues.CurrentDetector != "antivirus"))
      //{
      //  lFidoReturnValues.MachineScore += avNotInstalled;
      //}

      return lFidoReturnValues;
    }

    public static FidoReturnValues GetAssetScore(FidoReturnValues lFidoReturnValues, bool isPaired)
    {
      //check if hostname is in PCI affected zone
      if (lFidoReturnValues.Hostname == null) return lFidoReturnValues;
      var sHostname = new SqLiteDB().ExecuteScalar(@"select asset_hostname from configs_posture_asset");
      var sHostnameAry = sHostname.Split(',');
      var isContainsHost = false;

      if (!sHostnameAry.Any()) return lFidoReturnValues;
      Console.WriteLine(@"Scoring physical asset.");
      foreach (var name in sHostnameAry)
      {
        if ((lFidoReturnValues.Hostname.ToLower().Contains(name) && name != String.Empty))
        {
          isContainsHost = true;
        }
        if ((isPaired == false) && (isContainsHost))
        {
          lFidoReturnValues.IsPCI = true;
        }
      }

      //check if subnet is in PCI affect zone
      var isContainsSubnet = false;
      if (lFidoReturnValues.SrcIP != null)
      {
        Console.WriteLine(@"Scoring physical PCI asset.");
        var sSubnet = new SqLiteDB().ExecuteScalar(@"select subnet from configs_posture_asset");
        var sSubnetAry = sSubnet.Split(',');

        if (sSubnetAry.Any())
        {
          foreach (var subnet in sSubnetAry)
          {
            if ((lFidoReturnValues.SrcIP.Contains(subnet)) && subnet != String.Empty)
            {
              isContainsSubnet = true;
            }
            if ((isPaired == false) && (isContainsSubnet))
            {
              lFidoReturnValues.IsPCI = true;
            }
          }
        }
      }

      if ((isPaired) && (isContainsSubnet) && (isContainsHost))
      {
        lFidoReturnValues.IsPCI = true;
      }

      return lFidoReturnValues;
    }

    public static double AntiVirusScore(FidoReturnValues lFidoReturnValues)
    {
      //var iTrojanMultiplier = Object_Fido_Configs.GetAsInt("fido.detectors.antivirus.trojanmultiplier", 0);
      //var iTrojanWeight = Object_Fido_Configs.GetAsInt("fido.detectors.antivirus.trojanweight", 0);
      //var iRegularMultiplier = Object_Fido_Configs.GetAsInt("fido.detectors.antivirus.regularmultiplier", 0);
      //var iRegularWeight = Object_Fido_Configs.GetAsInt("fido.detectors.antivirus.regularweight", 0);
      //var sNewThreatName = lFidoReturnValues.Antivirus.ThreatName.Split('/');
      //if ((sNewThreatName != null) && (sNewThreatName[0].ToLower() == "troj"))
      //{
      //  lFidoReturnValues = AntiVirusTrojanReturnScore(lFidoReturnValues, iTrojanWeight, iTrojanMultiplier, iRegularWeight, iRegularMultiplier);
      //}
      //else
      //{
      //  lFidoReturnValues = AntiVirusGenericReturnScore(lFidoReturnValues, iTrojanWeight, iTrojanMultiplier, iRegularWeight, iRegularMultiplier);
      //}

      return lFidoReturnValues.ThreatScore;
    }

    private static FidoReturnValues AntiVirusGenericReturnScore(FidoReturnValues lFidoReturnValues, int iTrojanWeight, int iTrojanMultiplier, int iRegularWeight, int iRegularMultiplier)
    {
      switch (lFidoReturnValues.Antivirus.ActionTaken.ToLower())
      {
        case "none":
          switch (lFidoReturnValues.Antivirus.Status.ToLower())
          {
            case "cleanable":
              lFidoReturnValues.ThreatScore += iTrojanWeight*iTrojanMultiplier;
              break;
            case "cleanup failed":
              lFidoReturnValues.ThreatScore += iTrojanWeight*iTrojanMultiplier + 5;
              break;
            case "restart required":
              lFidoReturnValues.ThreatScore += iTrojanWeight*iTrojanMultiplier;
              break;
            case "not cleanable":
              lFidoReturnValues.ThreatScore += iTrojanWeight*iTrojanMultiplier + 20;
              break;
          }
          break;
        case "partially removed":
          switch (lFidoReturnValues.Antivirus.Status.ToLower())
          {
            case "cleanable":
              lFidoReturnValues.ThreatScore += iRegularWeight*iRegularMultiplier;
              break;
            case "cleanup failed":
              lFidoReturnValues.ThreatScore += iRegularWeight*iRegularMultiplier;
              break;
            case "restart required":
              lFidoReturnValues.ThreatScore += iRegularWeight*iRegularMultiplier - 15;
              break;
            case "not cleanable":
              lFidoReturnValues.ThreatScore += iRegularWeight*iRegularMultiplier + 10;
              break;
          }
          break;
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues AntiVirusTrojanReturnScore(FidoReturnValues lFidoReturnValues, int iTrojanWeight, int iTrojanMultiplier, int iRegularWeight, int iRegularMultiplier)
    {
      switch (lFidoReturnValues.Antivirus.ActionTaken.ToLower())
      {
        case "none":
          switch (lFidoReturnValues.Antivirus.Status.ToLower())
          {
            case "cleanable":
              lFidoReturnValues.ThreatScore += iTrojanWeight*iTrojanMultiplier;
              break;
            case "cleanup failed":
              lFidoReturnValues.ThreatScore += iTrojanWeight*iTrojanMultiplier + 20;
              break;
            case "restart required":
              lFidoReturnValues.ThreatScore += iTrojanWeight*iTrojanMultiplier - 10;
              break;
            case "not cleanable":
              lFidoReturnValues.ThreatScore += iTrojanWeight*iTrojanMultiplier + 40;
              break;
          }
          break;
        case "partially removed":
          switch (lFidoReturnValues.Antivirus.Status.ToLower())
          {
            case "cleanable":
              lFidoReturnValues.ThreatScore += iRegularWeight*iRegularMultiplier;
              break;
            case "cleanup failed":
              lFidoReturnValues.ThreatScore += iRegularWeight*iRegularMultiplier + 10;
              break;
            case "restart required":
              lFidoReturnValues.ThreatScore += iRegularWeight*iRegularMultiplier - 5;
              break;
            case "not cleanable":
              lFidoReturnValues.ThreatScore += iRegularWeight*iRegularMultiplier + 30;
              break;
          }
          break;
      }
      return lFidoReturnValues;
    }

    public static FidoReturnValues SetScoreValues(FidoReturnValues lFidoReturnValues)
    {
      lFidoReturnValues = SetThreatScore(lFidoReturnValues);
      lFidoReturnValues = SetUserScore(lFidoReturnValues);
      lFidoReturnValues = SetMachineScore(lFidoReturnValues);
      lFidoReturnValues.TotalScore = lFidoReturnValues.ThreatScore + lFidoReturnValues.MachineScore + lFidoReturnValues.UserScore;

      if (lFidoReturnValues.TotalScore > 100)
      {
        lFidoReturnValues.TotalScore = 100;
      }
      else
      {
        lFidoReturnValues.TotalScore = Math.Round(lFidoReturnValues.TotalScore / 5) * 5;
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues SetMachineScore(FidoReturnValues lFidoReturnValues)
    {
      if (lFidoReturnValues.MachineScore > 100)
      {
        lFidoReturnValues.MachineScore = 100;
      }
      else
      {
        lFidoReturnValues.MachineScore = Math.Round(lFidoReturnValues.MachineScore/5)*5;
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues SetUserScore(FidoReturnValues lFidoReturnValues)
    {
      if (lFidoReturnValues.UserScore > 100)
      {
        lFidoReturnValues.UserScore = 100;
      }
      else
      {
        lFidoReturnValues.UserScore = Math.Round(lFidoReturnValues.UserScore/5)*5;
      }
      return lFidoReturnValues;
    }

    private static FidoReturnValues SetThreatScore(FidoReturnValues lFidoReturnValues)
    {
      if (lFidoReturnValues.ThreatScore > 100)
      {
        lFidoReturnValues.ThreatScore = 100;
      }
      else
      {
        lFidoReturnValues.ThreatScore = Math.Round(lFidoReturnValues.ThreatScore/5)*5;
      }
      return lFidoReturnValues;
    }
  }
}
