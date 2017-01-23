using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Xml.Serialization;

namespace Fido_Main.Fido_Support.Objects.Jamf
{
  public class JamfReturnValues
  {
    [XmlRoot(ElementName = "computer")]
    public class ComputerList
    {
      [XmlElement(ElementName = "id")]
      public string Id { get; set; }
      [XmlElement(ElementName = "name")]
      public string Name { get; set; }
    }

    [XmlRoot(ElementName = "computers")]
    public class Computers
    {
      [XmlElement(ElementName = "size")]
      public string Size { get; set; }
      [XmlElement(ElementName = "computer")]
      public List<ComputerList> Computer { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "management_password_sha256")]
    public class Management_password_sha256
    {
      [DataMember]
      [XmlAttribute(AttributeName = "since")]
      public string Since { get; set; }
      [DataMember]
      [XmlText]
      public string Text { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "remote_management")]
    public class Remote_management
    {
      [DataMember]
      [XmlElement(ElementName = "managed")]
      public string Managed { get; set; }
      [DataMember]
      [XmlElement(ElementName = "management_username")]
      public string Management_username { get; set; }
      [DataMember]
      [XmlElement(ElementName = "management_password_sha256")]
      public Management_password_sha256 Management_password_sha256 { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "mdm_capable_users")]
    public class Mdm_capable_users
    {
      [DataMember]
      [XmlElement(ElementName = "mdm_capable_user")]
      public string Mdm_capable_user { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "site")]
    public class Site
    {
      [DataMember]
      [XmlElement(ElementName = "id")]
      public string Id { get; set; }
      [DataMember]
      [XmlElement(ElementName = "name")]
      public string Name { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "general")]
    public class General
    {
      [DataMember]
      [XmlElement(ElementName = "id")]
      public string Id { get; set; }
      [DataMember]
      [XmlElement(ElementName = "name")]
      public string Name { get; set; }
      [DataMember]
      [XmlElement(ElementName = "mac_address")]
      public string Mac_address { get; set; }
      [DataMember]
      [XmlElement(ElementName = "alt_mac_address")]
      public string Alt_mac_address { get; set; }
      [DataMember]
      [XmlElement(ElementName = "ip_address")]
      public string Ip_address { get; set; }
      [DataMember]
      [XmlElement(ElementName = "serial_number")]
      public string Serial_number { get; set; }
      [DataMember]
      [XmlElement(ElementName = "udid")]
      public string Udid { get; set; }
      [DataMember]
      [XmlElement(ElementName = "jamf_version")]
      public string Jamf_version { get; set; }
      [DataMember]
      [XmlElement(ElementName = "platform")]
      public string Platform { get; set; }
      [DataMember]
      [XmlElement(ElementName = "barcode_1")]
      public string Barcode_1 { get; set; }
      [DataMember]
      [XmlElement(ElementName = "barcode_2")]
      public string Barcode_2 { get; set; }
      [DataMember]
      [XmlElement(ElementName = "asset_tag")]
      public string Asset_tag { get; set; }
      [DataMember]
      [XmlElement(ElementName = "remote_management")]
      public Remote_management Remote_management { get; set; }
      [DataMember]
      [XmlElement(ElementName = "mdm_capable")]
      public string Mdm_capable { get; set; }
      [DataMember]
      [XmlElement(ElementName = "mdm_capable_users")]
      public Mdm_capable_users Mdm_capable_users { get; set; }
      [DataMember]
      [XmlElement(ElementName = "report_date")]
      public string Report_date { get; set; }
      [DataMember]
      [XmlElement(ElementName = "report_date_epoch")]
      public string Report_date_epoch { get; set; }
      [DataMember]
      [XmlElement(ElementName = "report_date_utc")]
      public string Report_date_utc { get; set; }
      [DataMember]
      [XmlElement(ElementName = "last_contact_time")]
      public string Last_contact_time { get; set; }
      [DataMember]
      [XmlElement(ElementName = "last_contact_time_epoch")]
      public string Last_contact_time_epoch { get; set; }
      //[DataMember]
      [XmlElement(ElementName = "last_contact_time_utc")]
      public string Last_contact_time_utc { get; set; }
      [DataMember]
      [XmlElement(ElementName = "initial_entry_date")]
      public string Initial_entry_date { get; set; }
      [DataMember]
      [XmlElement(ElementName = "initial_entry_date_epoch")]
      public string Initial_entry_date_epoch { get; set; }
      [DataMember]
      [XmlElement(ElementName = "initial_entry_date_utc")]
      public string Initial_entry_date_utc { get; set; }
      [DataMember]
      [XmlElement(ElementName = "last_cloud_backup_date_epoch")]
      public string Last_cloud_backup_date_epoch { get; set; }
      [DataMember]
      [XmlElement(ElementName = "last_cloud_backup_date_utc")]
      public string Last_cloud_backup_date_utc { get; set; }
      [DataMember]
      [XmlElement(ElementName = "distribution_point")]
      public string Distribution_point { get; set; }
      [DataMember]
      [XmlElement(ElementName = "sus")]
      public string Sus { get; set; }
      [DataMember]
      [XmlElement(ElementName = "netboot_server")]
      public string Netboot_server { get; set; }
      [DataMember]
      [XmlElement(ElementName = "site")]
      public Site Site { get; set; }
      [DataMember]
      [XmlElement(ElementName = "itunes_store_account_is_active")]
      public string Itunes_store_account_is_active { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "location")]
    public class Location
    {
      [DataMember]
      [XmlElement(ElementName = "username")]
      public string Username { get; set; }
      [DataMember]
      [XmlElement(ElementName = "real_name")]
      public string Real_name { get; set; }
      [DataMember]
      [XmlElement(ElementName = "email_address")]
      public string Email_address { get; set; }
      [DataMember]
      [XmlElement(ElementName = "position")]
      public string Position { get; set; }
      [DataMember]
      [XmlElement(ElementName = "phone")]
      public string Phone { get; set; }
      [DataMember]
      [XmlElement(ElementName = "department")]
      public string Department { get; set; }
      [DataMember]
      [XmlElement(ElementName = "building")]
      public string Building { get; set; }
      [DataMember]
      [XmlElement(ElementName = "room")]
      public string Room { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "purchasing")]
    public class Purchasing
    {
      [DataMember]
      [XmlElement(ElementName = "is_purchased")]
      public string Is_purchased { get; set; }
      [DataMember]
      [XmlElement(ElementName = "is_leased")]
      public string Is_leased { get; set; }
      [DataMember]
      [XmlElement(ElementName = "po_number")]
      public string Po_number { get; set; }
      [DataMember]
      [XmlElement(ElementName = "vendor")]
      public string Vendor { get; set; }
      [DataMember]
      [XmlElement(ElementName = "applecare_id")]
      public string Applecare_id { get; set; }
      [DataMember]
      [XmlElement(ElementName = "purchase_price")]
      public string Purchase_price { get; set; }
      [DataMember]
      [XmlElement(ElementName = "purchasing_account")]
      public string Purchasing_account { get; set; }
      [DataMember]
      [XmlElement(ElementName = "po_date")]
      public string Po_date { get; set; }
      [DataMember]
      [XmlElement(ElementName = "po_date_epoch")]
      public string Po_date_epoch { get; set; }
      [DataMember]
      [XmlElement(ElementName = "po_date_utc")]
      public string Po_date_utc { get; set; }
      [DataMember]
      [XmlElement(ElementName = "warranty_expires")]
      public string Warranty_expires { get; set; }
      [DataMember]
      [XmlElement(ElementName = "warranty_expires_epoch")]
      public string Warranty_expires_epoch { get; set; }
      [DataMember]
      [XmlElement(ElementName = "warranty_expires_utc")]
      public string Warranty_expires_utc { get; set; }
      [DataMember]
      [XmlElement(ElementName = "lease_expires")]
      public string Lease_expires { get; set; }
      [DataMember]
      [XmlElement(ElementName = "lease_expires_epoch")]
      public string Lease_expires_epoch { get; set; }
      [DataMember]
      [XmlElement(ElementName = "lease_expires_utc")]
      public string Lease_expires_utc { get; set; }
      [DataMember]
      [XmlElement(ElementName = "life_expectancy")]
      public string Life_expectancy { get; set; }
      [DataMember]
      [XmlElement(ElementName = "purchasing_contact")]
      public string Purchasing_contact { get; set; }
      [DataMember]
      [XmlElement(ElementName = "os_applecare_id")]
      public string Os_applecare_id { get; set; }
      [DataMember]
      [XmlElement(ElementName = "os_maintenance_expires")]
      public string Os_maintenance_expires { get; set; }
      [DataMember]
      [XmlElement(ElementName = "attachments")]
      public string Attachments { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "peripherals")]
    public class Peripherals
    {
      [DataMember]
      [XmlElement(ElementName = "size")]
      public string Size { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "partition")]
    public class Partition
    {
      [DataMember]
      [XmlElement(ElementName = "name")]
      public string Name { get; set; }
      [DataMember]
      [XmlElement(ElementName = "size")]
      public string Size { get; set; }
      [DataMember]
      [XmlElement(ElementName = "type")]
      public string Type { get; set; }
      [DataMember]
      [XmlElement(ElementName = "partition_capacity_mb")]
      public string Partition_capacity_mb { get; set; }
      [DataMember]
      [XmlElement(ElementName = "percentage_full")]
      public string Percentage_full { get; set; }
      [DataMember]
      [XmlElement(ElementName = "filevault_status")]
      public string Filevault_status { get; set; }
      [DataMember]
      [XmlElement(ElementName = "filevault_percent")]
      public string Filevault_percent { get; set; }
      [DataMember]
      [XmlElement(ElementName = "filevault2_status")]
      public string Filevault2_status { get; set; }
      [DataMember]
      [XmlElement(ElementName = "filevault2_percent")]
      public string Filevault2_percent { get; set; }
      [DataMember]
      [XmlElement(ElementName = "lvgUUID")]
      public string LvgUUID { get; set; }
      [DataMember]
      [XmlElement(ElementName = "lvUUID")]
      public string LvUUID { get; set; }
      [DataMember]
      [XmlElement(ElementName = "pvUUID")]
      public string PvUUID { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "device")]
    public class Device
    {
      [DataMember]
      [XmlElement(ElementName = "disk")]
      public string Disk { get; set; }
      [DataMember]
      [XmlElement(ElementName = "model")]
      public string Model { get; set; }
      [DataMember]
      [XmlElement(ElementName = "revision")]
      public string Revision { get; set; }
      [DataMember]
      [XmlElement(ElementName = "serial_number")]
      public string Serial_number { get; set; }
      [DataMember]
      [XmlElement(ElementName = "size")]
      public string Size { get; set; }
      [DataMember]
      [XmlElement(ElementName = "drive_capacity_mb")]
      public string Drive_capacity_mb { get; set; }
      [DataMember]
      [XmlElement(ElementName = "connection_type")]
      public string Connection_type { get; set; }
      [DataMember]
      [XmlElement(ElementName = "smart_status")]
      public string Smart_status { get; set; }
      [DataMember]
      [XmlElement(ElementName = "partition")]
      public Partition Partition { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "storage")]
    public class Storage
    {
      [DataMember]
      [XmlElement(ElementName = "device")]
      public List<Device> Device { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "printer")]
    public class Printer
    {
      [DataMember]
      [XmlElement(ElementName = "name")]
      public string Name { get; set; }
      [DataMember]
      [XmlElement(ElementName = "uri")]
      public string Uri { get; set; }
      [DataMember]
      [XmlElement(ElementName = "type")]
      public string Type { get; set; }
      [DataMember]
      [XmlElement(ElementName = "location")]
      public string Location { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "mapped_printers")]
    public class Mapped_printers
    {
      [DataMember]
      [XmlElement(ElementName = "printer")]
      public List<Printer> Printer { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "hardware")]
    public class Hardware
    {
      [DataMember]
      [XmlElement(ElementName = "make")]
      public string Make { get; set; }
      [DataMember]
      [XmlElement(ElementName = "model")]
      public string Model { get; set; }
      [DataMember]
      [XmlElement(ElementName = "model_identifier")]
      public string Model_identifier { get; set; }
      [DataMember]
      [XmlElement(ElementName = "os_name")]
      public string Os_name { get; set; }
      [DataMember]
      [XmlElement(ElementName = "os_version")]
      public string Os_version { get; set; }
      [DataMember]
      [XmlElement(ElementName = "os_build")]
      public string Os_build { get; set; }
      [DataMember]
      [XmlElement(ElementName = "active_directory_status")]
      public string Active_directory_status { get; set; }
      [DataMember]
      [XmlElement(ElementName = "service_pack")]
      public string Service_pack { get; set; }
      [DataMember]
      [XmlElement(ElementName = "processor_type")]
      public string Processor_type { get; set; }
      [DataMember]
      [XmlElement(ElementName = "processor_architecture")]
      public string Processor_architecture { get; set; }
      [DataMember]
      [XmlElement(ElementName = "processor_speed")]
      public string Processor_speed { get; set; }
      [DataMember]
      [XmlElement(ElementName = "processor_speed_mhz")]
      public string Processor_speed_mhz { get; set; }
      [DataMember]
      [XmlElement(ElementName = "number_processors")]
      public string Number_processors { get; set; }
      [DataMember]
      [XmlElement(ElementName = "total_ram")]
      public string Total_ram { get; set; }
      [DataMember]
      [XmlElement(ElementName = "total_ram_mb")]
      public string Total_ram_mb { get; set; }
      [DataMember]
      [XmlElement(ElementName = "boot_rom")]
      public string Boot_rom { get; set; }
      [DataMember]
      [XmlElement(ElementName = "bus_speed")]
      public string Bus_speed { get; set; }
      [DataMember]
      [XmlElement(ElementName = "bus_speed_mhz")]
      public string Bus_speed_mhz { get; set; }
      [DataMember]
      [XmlElement(ElementName = "battery_capacity")]
      public string Battery_capacity { get; set; }
      [DataMember]
      [XmlElement(ElementName = "cache_size")]
      public string Cache_size { get; set; }
      [DataMember]
      [XmlElement(ElementName = "cache_size_kb")]
      public string Cache_size_kb { get; set; }
      [DataMember]
      [XmlElement(ElementName = "available_ram_slots")]
      public string Available_ram_slots { get; set; }
      [DataMember]
      [XmlElement(ElementName = "optical_drive")]
      public string Optical_drive { get; set; }
      [DataMember]
      [XmlElement(ElementName = "nic_speed")]
      public string Nic_speed { get; set; }
      [DataMember]
      [XmlElement(ElementName = "smc_version")]
      public string Smc_version { get; set; }
      [DataMember]
      [XmlElement(ElementName = "storage")]
      public Storage Storage { get; set; }
      [DataMember]
      [XmlElement(ElementName = "mapped_printers")]
      public Mapped_printers Mapped_printers { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "licensed_software")]
    public class Licensed_software
    {
      [DataMember]
      [XmlElement(ElementName = "name")]
      public List<string> Name { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "available_software_updates")]
    public class Available_software_updates
    {
      [DataMember]
      [XmlElement(ElementName = "name")]
      public string Name { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "update")]
    public class Update
    {
      [DataMember]
      [XmlElement(ElementName = "name")]
      public string Name { get; set; }
      [DataMember]
      [XmlElement(ElementName = "package_name")]
      public string Package_name { get; set; }
      [DataMember]
      [XmlElement(ElementName = "version")]
      public string Version { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "available_updates")]
    public class Available_updates
    {
      [DataMember]
      [XmlElement(ElementName = "update")]
      public Update Update { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "running_services")]
    public class Running_services
    {
      [DataMember]
      [XmlElement(ElementName = "name")]
      public List<string> Name { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "application")]
    public class Application
    {
      [DataMember]
      [XmlElement(ElementName = "name")]
      public string Name { get; set; }
      [DataMember]
      [XmlElement(ElementName = "path")]
      public string Path { get; set; }
      [DataMember]
      [XmlElement(ElementName = "version")]
      public string Version { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "applications")]
    public class Applications
    {
      [DataMember]
      [XmlElement(ElementName = "size")]
      public string Size { get; set; }
      [DataMember]
      [XmlElement(ElementName = "application")]
      public List<Application> Application { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "fonts")]
    public class Fonts
    {
      [DataMember]
      [XmlElement(ElementName = "size")]
      public string Size { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "plugin")]
    public class Plugin
    {
      [DataMember]
      [XmlElement(ElementName = "name")]
      public string Name { get; set; }
      [DataMember]
      [XmlElement(ElementName = "path")]
      public string Path { get; set; }
      [DataMember]
      [XmlElement(ElementName = "version")]
      public string Version { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "plugins")]
    public class Plugins
    {
      [DataMember]
      [XmlElement(ElementName = "size")]
      public string Size { get; set; }
      [DataMember]
      [XmlElement(ElementName = "plugin")]
      public List<Plugin> Plugin { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "software")]
    public class Software
    {
      [DataMember]
      [XmlElement(ElementName = "unix_executables")]
      public string Unix_executables { get; set; }
      [DataMember]
      [XmlElement(ElementName = "licensed_software")]
      public Licensed_software Licensed_software { get; set; }
      [DataMember]
      [XmlElement(ElementName = "installed_by_casper")]
      public string Installed_by_casper { get; set; }
      [DataMember]
      [XmlElement(ElementName = "installed_by_installer_swu")]
      public string Installed_by_installer_swu { get; set; }
      [DataMember]
      [XmlElement(ElementName = "cached_by_casper")]
      public string Cached_by_casper { get; set; }
      [DataMember]
      [XmlElement(ElementName = "available_software_updates")]
      public Available_software_updates Available_software_updates { get; set; }
      [DataMember]
      [XmlElement(ElementName = "available_updates")]
      public Available_updates Available_updates { get; set; }
      [DataMember]
      [XmlElement(ElementName = "running_services")]
      public Running_services Running_services { get; set; }
      [DataMember]
      [XmlElement(ElementName = "applications")]
      public Applications Applications { get; set; }
      [DataMember]
      [XmlElement(ElementName = "fonts")]
      public Fonts Fonts { get; set; }
      [DataMember]
      [XmlElement(ElementName = "plugins")]
      public Plugins Plugins { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "extension_attribute")]
    public class Extension_attribute
    {
      [DataMember]
      [XmlElement(ElementName = "id")]
      public string Id { get; set; }
      [DataMember]
      [XmlElement(ElementName = "name")]
      public string Name { get; set; }
      [DataMember]
      [XmlElement(ElementName = "type")]
      public string Type { get; set; }
      [DataMember]
      [XmlElement(ElementName = "value")]
      public string Value { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "extension_attributes")]
    public class Extension_attributes
    {
      [DataMember]
      [XmlElement(ElementName = "extension_attribute")]
      public List<Extension_attribute> Extension_attribute { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "computer_group_memberships")]
    public class Computer_group_memberships
    {
      [DataMember]
      [XmlElement(ElementName = "group")]
      public List<string> Group { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "user")]
    public class User
    {
      [DataMember]
      [XmlElement(ElementName = "name")]
      public string Name { get; set; }
      [DataMember]
      [XmlElement(ElementName = "realname")]
      public string Realname { get; set; }
      [DataMember]
      [XmlElement(ElementName = "uid")]
      public string Uid { get; set; }
      [DataMember]
      [XmlElement(ElementName = "home")]
      public string Home { get; set; }
      [DataMember]
      [XmlElement(ElementName = "home_size")]
      public string Home_size { get; set; }
      [DataMember]
      [XmlElement(ElementName = "home_size_mb")]
      public string Home_size_mb { get; set; }
      [DataMember]
      [XmlElement(ElementName = "administrator")]
      public string Administrator { get; set; }
      [DataMember]
      [XmlElement(ElementName = "filevault_enabled")]
      public string Filevault_enabled { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "local_accounts")]
    public class Local_accounts
    {
      [DataMember]
      [XmlElement(ElementName = "user")]
      public List<User> User { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "groups_accounts")]
    public class Groups_accounts
    {
      [DataMember]
      [XmlElement(ElementName = "computer_group_memberships")]
      public Computer_group_memberships Computer_group_memberships { get; set; }
      [DataMember]
      [XmlElement(ElementName = "local_accounts")]
      public Local_accounts Local_accounts { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "iphones")]
    public class Iphones
    {
      [DataMember]
      [XmlElement(ElementName = "size")]
      public string Size { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "is_removable")]
    public class Is_removable
    {
      [DataMember]
      [XmlAttribute(AttributeName = "since")]
      public string Since { get; set; }
      [DataMember]
      [XmlText]
      public string Text { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "configuration_profile")]
    public class Configuration_profile
    {
      [DataMember]
      [XmlElement(ElementName = "id")]
      public string Id { get; set; }
      [DataMember]
      [XmlElement(ElementName = "name")]
      public string Name { get; set; }
      [DataMember]
      [XmlElement(ElementName = "uuid")]
      public string Uuid { get; set; }
      [DataMember]
      [XmlElement(ElementName = "is_removable")]
      public Is_removable Is_removable { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "configuration_profiles")]
    public class Configuration_profiles
    {
      [DataMember]
      [XmlElement(ElementName = "size")]
      public string Size { get; set; }
      [DataMember]
      [XmlElement(ElementName = "configuration_profile")]
      public Configuration_profile Configuration_profile { get; set; }
    }

    [DataContract]
    [XmlRoot(ElementName = "computer")]
    public class Computer
    {
      [DataMember]
      [XmlElement(ElementName = "general")]
      public General General { get; set; }
      [DataMember]
      [XmlElement(ElementName = "location")]
      public Location Location { get; set; }
      [DataMember]
      [XmlElement(ElementName = "purchasing")]
      public Purchasing Purchasing { get; set; }
      [DataMember]
      [XmlElement(ElementName = "peripherals")]
      public Peripherals Peripherals { get; set; }
      [DataMember]
      [XmlElement(ElementName = "hardware")]
      public Hardware Hardware { get; set; }
      [DataMember]
      [XmlElement(ElementName = "software")]
      public Software Software { get; set; }
      [DataMember]
      [XmlElement(ElementName = "extension_attributes")]
      public Extension_attributes Extension_attributes { get; set; }
      [DataMember]
      [XmlElement(ElementName = "groups_accounts")]
      public Groups_accounts Groups_accounts { get; set; }
      [DataMember]
      [XmlElement(ElementName = "iphones")]
      public Iphones Iphones { get; set; }
      [DataMember]
      [XmlElement(ElementName = "configuration_profiles")]
      public Configuration_profiles Configuration_profiles { get; set; }
    }
  }
}
