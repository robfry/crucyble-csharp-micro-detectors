namespace FIDO_Detector.Fido_Support.Rest
{
  public static class Fido_Rest_Connection_Factory
  {

    public static void CreateRestCall (DetectorType DetectorType)
    {
      switch (DetectorType)
      {
        case DetectorType.protectwise:
          break;
        case DetectorType.cyphort:
          break;
        case DetectorType.niddel:
          break;
        case DetectorType.pan:
          break;
        case DetectorType.jamf:
          return;
          break;
        case DetectorType.carbonblack:
          break;
        default:
          return;
          break;
      }
    }
  }
}
