# Inventorying Existing Environment

This example shows a parent-child domain architecture with DAG, where Exchange server is installed in a child domain with hardware load balancer.

- Have an estimation of how many mailboxes on each existing Exchange server
  - Get-Mailbox | Group-Object -Property:Database | Select Name,Count | ft -auto

- Collect AD forest functional level info
  - Get-ADForest

- Collect domain controller version in AD
  - Get-ADDomainController | Select Name, OperatingSystem

- Client Access Namespace (used by client to connect to Exchange)
  - Inventory PowerShell – Collect internal and external domain names for each of the below
    - Autodiscover (SCP)
      - Get-ClientAccessServer | Select Identity,AutoDiscoverServiceInternalUri
    - Outlook Anywhere (RPC over HTTPS)
      - Get-OutlookAnywhere -ADPropertiesOnly | Select Server,Internalhostname,Externalhostname
    - OWA
      - Get-OWAVirtualDirectory -ADPropertiesOnly | Select Server,InternalURL,ExternalURL
    - ECP
      - Get-ECPVirtualDirectory -ADPropertiesOnly | Select Server,InternalURL,ExternalURL
    - Offline Address Book (OAB)
      - Get-OABVirtualDirectory -ADPropertiesOnly | Select Server,InternalURL,ExternalURL
    - Exchange Web Services (EWS)
      - Get-WebServicesVirtualDirectory -ADPropertiesOnly | Select Server,InternalURL,ExternalURL
    - MAPI/HTTP
      - Get-MAPIVirtualDirectory -ADPropertiesOnly | Select Server,InternalURL,ExternalURL
    - ActiveSync
      - Get-ActiveSyncVirtualDirectory -ADPropertiesOnly | Select Server,InternalURL,ExternalURL
- SSL Certificates
  - For Exchange ActiveSync, Outlook Anywhere, Outlook Web App, etc.
  - Requirements
    - Matches the server name to which clients connect
    - Still within validity period
    - Issued by a trusted certificate authority
  - Reusing existing certificates for new Exchange server is acceptable
    - Provided that client connect to an **alias address** instead of addresses specifying server hostnames (e.g. mail.company.com instead of EXCH13.company.com)
  - Inventory PowerShell
    - Take note of output with **W** which are certificates for IIS (not **I** which are for IMAP)
      - Get-ExchangeCertificate
    - Take note of CertificateDomains which are covered by the domain, and the validity status
      - Get-ExchangeCertificate -Thumprint &lt;From\_Above\_Command&gt; | fl
- Mailbox Storage Quotas
  - Beware of default mailbox quota – For Exchange 2016, it is 2GB by default
    - Mailbox migration fails if size exceeds target database
    - New databases should be configured with same or larger quotas
  - Inventory PowerShell (second command supports querying Exchange 2010, if exists, from newer Exchange Management Shell)
    - Get-MailboxDatabase | Select Name,\*Quota\*
    - Get-MailboxDatabase -IncludePreExchange2013| Select Name,\*Quota\*

- Email Routing Topology and Transport
  - Internal mail flow between supported Exchange servers (Exchange 2010 &lt;&gt; 2013 &lt;&gt; 2016) is automatic (no further configuration required)
  - Inbound mail flow to the Internet
    - Acquire internal DNS MX record:
      - Resolve-DnsName -Type MX -Name mail.company.com -Server &lt;internal\_DNS&gt;
      - Resolve-DnsName -Type A  -Name mail.company.com -Server &lt;internal\_DNS&gt;
    - Alternatively
      - nslookup -&gt; server internal\_DNS\_Server -&gt; set type=MX -&gt; mail.company.com
      - nslookup -&gt; server internal\_DNS\_Server -&gt; set type=A -&gt; mail.company.com
    - Acquire external DNS MX and A record:
      - Resolve-DnsName -Type MX -Name mail.company.com -Server 8.8.8.8
      - Resolve-DnsName -Type A -Name mail.company.com -Server 8.8.8.8
    - Alternatively
      - nslookup -&gt; server 8.8.8.8 -&gt; set type=MX -&gt; mail.company.com
      - nslookup -&gt; server 8.8.8.8 -&gt; set type=A -&gt; mail.company.com
  - Outbound mail flow to the Internet
    - Acquire info of Send Connectors (for Outbound email)
      - Get-SendConnector
      - Get-SendConnector | fl
        - Watch out for SmartHosts and SmartHostsString to check whether there is any use of a smart host (it should be empty if not)
        - Watch out for SourceTransportServer to check whether the source transport servers that are currently in use (i.e. existing Exchange servers)

- Involves any non-Exchange servers? Internal application may send email via relay connectors
  - Check devices, services and applications which use SMTP services
    - Backup applications which send notifications (e.g. Veeam, Backup Exec)
    - Anti-malware or anti-spam (e.g. Symantec Endpoint Protection Manager)
    - Virtualization (e.g. vCenter, System Center Virtual Machine Manager)
    - Voice or telephony
    - SMS or fax gateways
  - Acquire info of Receive Connectors (for Relay connectors)
    - Get-ReceiveConnector -Server &lt;Server\_Name&gt;
      - Look for anything other than the below, which probably states &quot;Relay&quot; or something with an address binding or {0.0.0.0:25}
      - For Exchange 2010, ignore &quot;Default &lt;Server\_Name&gt;&quot; and &quot;Client &lt;Server\_Name&gt;&quot;
      - For Exchange 2013, ignore &quot;Default &lt;Server\_Name&gt;&quot;, &quot;Client Proxy &lt;Server\_Name&gt;&quot;, &quot;Default Frontend &lt;Server\_Name&gt;&quot;, &quot;Outbound Proxy Frontend &lt;Server\_Name&gt;&quot;, &quot;Client Frontend &lt;Server\_Name&gt;&quot;
  - Once found out, look for the remote IP Ranges of it (i.e. IP addresses which are allowed to relay email via that Exchange server
    - Get-ReceiveConnector &quot;Server\_Name\Receive\_Connector\_Name&quot; | Select RemoteIPRanges
  - Once an IP address is acquired, perform PTR DNS lookup using nslookup to find out its hostname/FQDN
    - nslookup &lt;IP\_address&gt;

- Public Folders
  - Inventorying existing public folders n existing Exchange Server
    - Get-PublicFolder -Recurse | Export-Clixml C:\PFMigration\Legacy\_PFStructure.xml
  - Acquire existing pubic folder statistics
    - Get-PublicFolderStatistics | Export-Clixml C:\PFMigration\Legacy\_PFStatistics.xml
  - Acquire public folder permissions
    - Get-PublicFolder -Recurse | Get-PublicFolderClientPermission | Select Identity, User -ExpandProperty AccessRights | Export-Clixml C:\PFMigration\Legacy\_PFperms.xml
  - Check if existing public folder names have backslash character &quot;\&quot; which is invalid
    - Get-PublicFolderStatistics -ResultSize Unlimited | Where {$\_.Name -Like &quot;\*\\*&quot;} } | fl name,identity
  - Watch out for existing pubic folder migration job
    - Get-OrganizationConfig | fl PublicFoldersLockedforMigration,PublicFolderMigrationComplete

# Exchange 2016 Changes

- Deprecation of Outlook Anywhere (RPC-over-HTTP) with MAPI-over-HTTP (enabled by default – introduced since Exchange 2013 SP1)
- Only Mailbox server role and Edge Transport server role (Exchange 2013 additionally includes Client Access Server, while Exchange 2010 includes Hub Transport and Client Access Server)
- Co-existence: Exchange 2010, 2013 and 2016 can proxy for one another (For Exchange 2010, Outlook Anywhere has to be used)
- Exchange requirements
  - Exchange 2010 SP3 with RU11 or later
  - Exchange 2013 CU10 or later
  - AD requirements
    - All domain controllers in the forest must be Windows Server 2008 or later
    - Forest functional level of Windows 2008 or higher (2008 R2 or higher if any Windows Server 2016 Domain Controller is in the environment)
- Outlook client requirements (Latest available service packs and updates recommended)
	- Windows: Outlook 2016, 2013, and 2010
	- Mac OS X: Outlook for Mac for Office 365 / Outlook for Mac 2011
- Introduction of Public Folder mailboxes – no more legacy Public Folders

# Installing Exchange - Implementing Exchange Co-Existence

1. Prepare privileges of account used during setup - root domain administrator account
   - Domain Admin, Enterprise Admin and Schema Admin as well as Organization Management
   - Copy setup media of Exchange and related dependencies (including to a root DC)
   - Raise forest functional level to 2003 native at a minimum (if required)
2. Refer to https://docs.microsoft.com/en-us/exchange/plan-and-deploy/prerequisites?view=exchserver-2016 for the latest prerequisites
3. Confirm PowerShell v4.0 is available
4. Confirm .NET Framework 4.5.2 is available
5. Confirm Windows components and Unified Communications Managed API 4.0 Core Runtime 64-bit are installed
   - Acquire the PowerShell command (Install-WindowsFeature…) to install Windows components from [https://technet.microsoft.com/en-us/library/bb691354%28v=exchg.160%29.aspx](https://technet.microsoft.com/en-us/library/bb691354%28v=exchg.160%29.aspx)
6. Log on to a DC in forest domain
   - Perform schema extensions: `setup /PrepareSchema /IAcceptExchangeServerLicenseTerms`
   - Perform Active Directory preparation: `setup /PrepareAD /IAcceptExchangeServerLicenseTerms`
   - Perform domain preparation: `setup /Preparedomain /IAcceptExchangeServerLicenseTerms`
7. Add root domain groups to ‘local administrators groups’ on each target Exchange mailbox server in staff domain
   - `ROOTDOMAIN\Exchange Trusted Subsystem`
   - `ROOTDOMAIN\Organization Management`
8. Install Exchange 2016 mailbox servers with root domain administrator account

# Avoiding Possible Impacts

- End user
  - Offline Address Book
    - Confirm existing mailbox databases have an Offline Address Book configured instead of leaving it blank
      - Each mailbox database in existing Exchange servers should have an office address book (e.g. the default one) assigned; otherwise, users may face a problem of unknowingly downloading the new OAB in Exchange 2016 which could take a lot of bandwidth

- Client connectivity
  - Autodiscover Service Connection Point (SCP)
    - Newly installed Exchange server has a default SCP URI of the server&#39;s FQDN (e.g. EXCH16.company.com), which generates certificate errors
    - Fix:
      - Get-ClientAccessServer -Identity EXCH16 | Select Name,AutoDiscoverServiceInternalUri
      - Set-ClientAccessServer -Identity EXCH16 -AutoDiscoverServiceInternalUri [https://mail.company.com/Autodisocver/Autodiscover.xml](https://mail.company.com/Autodisocver/Autodiscover.xml)
    - Ignore the AutoDiscover virtual directory setting which is not used for AutoDiscover – only SCP is used for AutoDiscover in an internal environment
- Mail flow
  - Internal to Internal Exchange servers
  - Inbound from the Internet
  - Outbound to the Internet
  - SMTP relay connectors

# Exchange Server 2016 Co-existence Tasks - Migrating Client Access

- Note
  - Manage object with the matching version of Exchange management tools
  - Client connectivity must go to the highest version of Exchange (except for 2013/2016 co-existence)
  - Email can route in or out of any version of Exchange
  - Internal Exchange to Exchange mail flow is automatic for Exchange 2010, 2013 and 2016 (Outlook Anywhere is leveraged)

1. Import the SSL certificate
    - Import from existing server to new server
    - Use them for SMTP and IIS
2. Configure the client access namespaces
    - Configure each HTTPS service with the same namespace as existing servers (virtual directories)
      - Defining variables
        - $InternalHostname = &quot;mail.company.com&quot;
        - $ExternalHostname = &quot;mail.company.com&quot;
        - $Server = &quot;EXCH16&quot;
      - Outlook Anywhere
        - Get-OutlookAnywhere -Server $Server | Set-OutlookAnywhere -ExternalHostname $ExternalHostname -InternalHostname $InternalHostname -ExternalClientsRequiresSsl $True -InternalClientsRequireSSL $true -DefaultAuthenticationMethod NTLM
      - OWA Virtual Directory
        - Get-OWAVirtualDirectory -Server $Server | Set-OWAVirtualDirectory -ExternalUrl https://$ExternalHostname/owa -InternalUrl https://$InternalHostname/owa
      - ECP Virtual Directory
        - Get-EcpVirtualDirectory -Server $Server | Set-EcpVirtualDirectory -ExternalUrl https://$ExternalHostname/ecp -InternalUrl https://$InternalHostname/ecp
      - ActiveSync Virtual Directory
        - Get-ActiveSyncVirtualDirectory -Server $Server | Set-ActiveSyncVirtualDirectory -ExternalUrl https://$ExternalHostname/Microsoft-Server-ActiveSync -InternalUrl https://$InternalHostname/Microsoft-Server-ActiveSync
      - EWS (Exchange Web Services) Virtual Directory
        - Get-WebServcesVirtualDirectory -Server $Server | Set-WebServicesVirtualDirectory -ExternalUrl https://$ExternalHostname/EWS/Exchange.asmx -InternalUrl https://$InternalHostname/EWS/Exchange.asmx
      - OAB (Offline Address Book) Virtual Directory
        - Get-OabVirtualDirectory -Server $Server | Set-OabVirtualDirectory -ExternalUrl https://$ExternalHostname/OAB -InternalUrl https://$InternalHostname/OAB
      - MAPI Virtual Directory
        - Get-MapiVirtualDirectory -Server $Server | Set-MapiVirtualDirectory -ExternalUrl https://$ExternalHostname/mapi -InternalUrl [https://$InternalHostname/mapi](https://%24InternalHostname/mapi)
      - Note: These changes do not make client connect to new Exchange server immediately; client will still connect to where DNS is resolving the namespace
    - Ensure new Exchange server uses existing authentication (e.g. form-based authentication with the same logon format)
    - Special concerns for Exchange 2010
      - Outlook Anywhere must be enabled
      - Check whether Outlook Anywhere is enabled
        - Get-ExchangeServer | Where {($\_.AdminDisplayVersion -Like &quot;Version 14\*&quot;) -And ($\_.ServerRole -Like &quot;\*ClientAccess\*&quot;)} | Get-ClientAccessServer | Select Name,OutlookAnywhereEnabled
    - IIS authentication must be configured for co-existence
      - Enable Outlook Anywhere and configure IIS authentication
        - Get-ExchangeServer | Where {($\_.AdminDisplayVersion -Like &quot;Version 14\*&quot;) -And ($\_.ServerRole -Like &quot;\*ClientAccess\*&quot;)} | Get-ClientAccessServer | Where {$\_.OutlookAnywhereEnabled -Eq $False} | Enable-OutlookAnywhere - ClientAuthenticationMethod Basic -SSLOffloading $False - ExternalHostName $hostname -IISAuthenticationMethods NTLM, Basic
3. Test the namespaces
    - Before DNS change (risky), use a hosts file for testing with a pilot group
      - Content of hosts file:
        - IP\_Address\_of\_Exchange\_2016 mail.company.com
4. Cutover namespaces to Exchange 2016
    - Lower DNS TTL to 1 minute (done earlier than what the TTL specifies)
    - Make DNS change for internal client (e.g. AD DNS server)
    - Make firewall change for external client (NAT settings)
5. New Exchange server is in production for client connectivity now
6. Test using exrca &gt; Exchange Server &gt; Microsoft Outlook Connectivity Tests &gt; Outlook Connectivity
    - Usual to see a few failed Autodiscover items, as long as the overall Autodiscover is successful

# Migrating Mail Flow

- Internal mail flow between Exchange servers
  - Change required: no need further setup (automatically established between installed Exchange servers)
  - Common issue: maximum allowed message size setting differs among Exchange servers
  - Compare using PowerShell the MaxMessageSize values among different servers
    - Get-ReceiveConnector | Select Name,MaxMessageSize
  - Fix using Set-ReceiveConnector
    - Get-ReceiveConnector -Server EXCH16 | Set-ReceiveConnector -MaxMessageSize 45MB
  - Test mail flow by sending an email from one internal mailbox to another
  - Outlook client: &quot;Request a Delivery Receipt&quot;

- Inbound mail flow from the Internet
  - Changes required
    - Firewall – by modifying NAT setting from the existing Exchange server to the new one, or
    - Email appliance or load balancer – by removing existing Exchange server and adding new one
  - Test mail flow using exrca &gt; Exchange Server &gt; Internet Email Tests &gt; Inbound SMTP Email
  - Analyze mail routing by pasting email header into exrca &gt; Message Analyzer

- Outbound mail flow to the Internet
  - Change required: EAC &gt; Mail Flow &gt; Edit Send Connector &gt; Source Server: Remove existing Exchange server; ensure only new Exchange server is in the list
  - Analyze mail routing by pasting email header into exrca &gt; Message Analyzer

- Devices and applications that use SMTP relay
  - Change required
  - EAC &gt; Mail Flow &gt; New Receive Connector
    - General tab
      - Name: Provide a name for a new relay connector, e.g. Relay EXCH16
      - Role: Frontend Transport
      - Type: Custom
      - Edit remote network settings by removing default 0.0.0.0-255.255.255.255 and adding IP addresses of devices and applications which send via this relay connector
    - Security tab
      - Tick &quot;Anonymous users&quot; under permission groups (leave all else unchecked except the first checkbox of TLS authentication)
  - Allow Exchange relay connector to relay email sent to external recipient
    - Get-ReceiveConnector &quot;EXCH16\Relay EXCH16&quot; | Add-ADPermission -User &#39;NT Authority\Anonymous Logon&#39; -ExtendedRights MS-Exch-SMTP-Accept-Any-Recipient
  - Fix existing misconfiguration on devices and applications (if any)
  - DNS alias should exist for SMTP, e.g. smtp.company.com
  - Devices and applications should be using DNS alias instead of the hostname or IP address of the server
  - Take the chance of migration to fix any nonoptimal settings

# Migrating Public Folder

- Note
  - Public folder mailbox is introduced in Exchange 2016 – no more legacy public folders
  - Exchange allows public folder mailboxes up to 100GB in size
  - Public folders may be migrated ahead of other mailboxes if they can sometimes be very large in size
  - For large environments, public folders may take few hours take time to finalizing cutover
  - One-way migration process (can roll back but lose changes since migration)
  - Follow Public Folder Batch Migration Guidance on TechNet
    - [https://technet.microsoft.com/en-us/library/dn912663(v=exchg.150).aspx](https://technet.microsoft.com/en-us/library/dn912663(v=exchg.150).aspx)

1. Download Public Folders migration scripts

    - [https://www.microsoft.com/en-us/download/details.aspx?id=38407](https://www.microsoft.com/en-us/download/details.aspx?id=38407)
    - Use these scripts to migrate public folders from Exchange 2007 or Exchange 2010 to Office 365 and Exchange Online, Exchange 2013, or later.

2. Extract scripts to C:\PFMigration

    - Create-PublicFolderMailboxesForMigration.ps1
    - CreatePublicFolderMailboxesForMigration.strings.psd1
    - Export-PublicFolderStatistics.ps1
    - Export-PublicFolderStatistics.strings.psd1
    - PublicFolderToMailboxMapGenerator.ps1
    - PublicFolderToMailboxMapGenerator.strings.psd1

3. Inventory existing public folders

    - Inventory existing public folders **on existing Exchange Server**
      - Get-PublicFolder -Recurse | Export-Clixml C:\PFMigration\Legacy\_PFStructure.xml
    - Acquire existing pubic folder statistics
      - Get-PublicFolderStatistics | Export-Clixml C:\PFMigration\Legacy\_PFStatistics.xml
    - Acquire public folder permissions
      - Get-PublicFolder -Recurse | Get-PublicFolderClientPermission | Select Identity, User -ExpandProperty AccessRights | Export-Clixml C:\PFMigration\Legacy\_PFperms.xml
    - Check if existing public folder names have backslash character &quot;\&quot; which is invalid
      - Get-PublicFolderStatistics -ResultSize Unlimited | Where {$\_.Name -Like &quot;\*\\*&quot;} } | fl name,identity
    - Watch out for existing pubic folder migration job
      - Get-OrganizationConfig | fl PublicFoldersLockedforMigration,PublicFolderMigrationComplete
    - Inventorying existing public folders and migration jobs **on new Exchange Server**
      - Get-PublicFolderMigrationRequest
      - Get-MigrationBatch | Where {$\_.MigrationType.ToString() -eq &quot;PublicFolder&quot;}
      - Get-Mailbox -PublicFolder

4. Generate CSV files on **existing Exchange server**

    - Export-PublicFolderStatistics.ps1
      - Run PowerShell commands to export public folder size statistics to CSV
        - cd C:\PFMigration
        - Export-PublicFolderStatistics.ps1 C:\PFMigration\PFSizeMap.csv Old\_Exch\_Server
      - Open CSV output with Excel and review the size. Exchange allows public folder mailboxes up to 100GB in size
    - PublicFolderToMailboxMapGenerator.ps1
      - Run PowerShell commands to export public folder map to CSV according to size requirements
      - e.g. 10GB max for each mailbox; if larger than 10GB, additional public folder mailbox names will be generated
        - ps1 10000000 C:\PFMigration\PFSizemap.csv C:\PFMigration\PFMailboxMap.csv
      - Open CSV and review. The CSV will be used for migration by New-MigrationBatch.

5. Create public folder mailboxes on **new Exchange server**

    - New-Mailbox -PublicFolder Mailbox1 -HoldForMigration:$true

6. Begin migration on **new Exchange server**

    - Creating a new migration batch using the generated PFMailboxMap.CSV
      - New-MigrationBatch -Name PFMigration -SourcePublicFolderDatabase (Get-PublicFolderDatabase -Server Old\_Exch\_Server) -CSVData (Get-Content C:\PFMigration\PFMailboxMap.csv -Encoding Byte) -NotificationEmails [recipient@company.com](mailto:recipient@company.com)
    - Start the migration batch
      - Start-MigrationBatch PFMigration
    - Acquire migration status
      - Get-MigrationUser -BatchId PFMigration
    - Optional: check migration status reporting email in the specified notification recipient mailbox

7. Lock public folders (outage required) on **existing Exchange server**

    - Set-OrganizationConfig -PublicFoldersLockedForMigration:$true
      - Note
        - It can take up to several hours for some environments
        - Effect of the -PublicFoldersLockedForMigration:$true parameter is pubic folders cannot be accessed (Error: Cannot expand the folder. Outlook cannot access this Public Folder right now. Please try again later.)

8. Finalize the migration (outage required) on **new Exchange server**

    - Enable public folders as remote
      - Set-OrganizationConfig -PublicFoldersEnabled Remote
    - Complete migration batch
      - Complete-MigrationBatch PFMigration
    - Get migration batch status (The command may be run a few times to keep tracking the statuses)
      - Get-MigrationBatch PFMigration

9. Test and unlock public folders on **new Exchange server**

    - After the below command is entered, the specified user can check his/her mailbox to see if public folders are accessible
      - Set-Mailbox username -DefaultPublicFolderMailbox PF\_Mailbox\_Name
    - Enable public folders as local
      - Set-OrganizationConfig -PublicFoldersEnabed Local

# Migrating Mailbox

  - Create a new or configure existing Exchange 2016 Mailbox Database
    - Reminder
      - Up to 5 DBs for Standard edition; 100 for Enterprise edition
    - Best practice
      - Separate transaction logs and DV to different storage volume (especially for non-HA implementations)
        - Examine the paths (EdbFilePath, LogFolderPath)
        - Get-MailboxDatabase | fl \*path\*
        - Change path
        - Move-DatabasePath -Identity DB\_Name -EdbFilePath &quot;Target\_Path\_1&quot; -LogFolderPath &quot;Target\_Path\_2&quot;
      - Other
        - Multiple small DBs is better than fewer large DBs (faster backup/restore/repair itmes)
          - Keep name short and identifiable &quot;DB01 vs Mailbox Database 1&quot;
          - Names must be unique
        - Rename DB
        - Set-MailboxDatabase &quot;Source DB Name&quot; -Name &quot;Target Name&quot;
    - Common Issue: Mailbox quota differs among different databases on existing and new servers (default: 2GB)
      - Acquire the existing quota information
        - Get-MailboxDatabase -IncludePreExchange2013 | Select Name,IssueWarningQuota,ProhibitSendQuota,ProhibitSendReceiveQuota
      - Fix by matching the quota of new server with that of the existing one
        - Get-MailboxDatabase -Server EXCH16 | Set-MailboxDatabase -IssueWarningQuota 5GB -ProhibitSendQuota 6GB -ProhibitSendReceiveQuota 10GB
    - Common Issue: Outlook Address Book not configured on existing Exchange servers
      - Check
        - Get-OfflineAddressBook
      - Fix by letting the new server use the OAB of the existing server
        - Get-MailboxDatabase -Server EXCH16 | Set-MailboxDatabase -OfflineAddressBook &quot;Default Offline Address Book (Previous Exchange)&quot;

- Prepare to migrate mailbox
  1. Exclude mailbox databases from provisioning (mailbox provisioning load balancer)
      - If no target DB is selected while creation of the migration batch, Exchange automatically distributes mailboxes across available mailbox databases
      - To Exclude a DB from provisioning
        - Set-MailboxDatabase &quot;DB name&quot; -IsExcludedFromProvisioning $true
  2. Schedule backup of the new server (make sure it is successful to backup and restore)
      - Massive amount of transaction logs could be generated during migration on the destination server which could take significant amount of disk space
      - May assume 1GB logs per 1GB mailbox data
      - Keep monitoring disk space usage on target server
  3. Migrate arbitration mailboxes first
      - Check
        - Get-Mailbox -Arbitration | Select name,database
      - Do
        - Get-Mailbox -Arbitration | New-MoveRequest
        - Get-MoveRequest | Get-MoveRequestStatistics
      - Verify
        - Check report &quot;Report: Download the report for this user&quot;. Look for start time and end time, error messages (if failed), etc.
  4. Move shared mailboxes and delegates altogether
      - Chief Executive Officer + his/her assistant
      - Specific team + specific shared mailbox
      - Equipment mailboxes + equipment manager
  5. Migration speed depends on size of mailboxes, performance of source and destination servers
  6. Online migration: migration can run while users are accessing their mailboxes
  7. Cutover: 95% of mailbox is migrated, then either auto-suspend, require manual completion or auto-complete
      - Completion stage involves disconnecting end user and displaying a message asking users to restart Outlook
      - Configure backup to truncate transaction log (which could outgrow available target storage)

# Decommission Servers

- Sanity Check
  - Client Access namespaces migrated?
    - Check DNS entries for Client Access namespaces
    - Check load balancer configuration
    - Review IIS logs (look for any user activity – see action list below)
  - Mail flow migrated?
  - Mailboxes migrated?
  - Public folders migrated?

- Action List
  - Confirm server no longer responsible for send connectors (Outbound email to the Internet)
    - Ensure only new Exchange is in source server (EAC &gt; Mail Flow &gt; Edit Send Connector &gt; Source Server)
  - Analyse usage via transport logs to confirm no SMTP traffic hitting a relay receive connector
    - Enable verbose protocol logging for a few hours or days to look for activity
      - Get-ReceiveConnector -Server Old\_Server | Select Identity,Enabled,ProtocolLogging
    - Should be _enabled_ and _verbose_. If not, configure them so
      - Set-ReceiveConnector &quot;Old\_Connector&quot; -ProtocolLoggingLevel Verbose
    - Check logs under C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\Logs\FrontEnd\ProtocolLog\SmtpReceive\RECV\*.LOG
    - Afterwards, disable verbose logging
      - Get-ReceiveConnector -Server Old\_Server | Where ($\_.ProtocolLoggingLevel -eq &quot;Verbose&quot;) | Set-ReceiveConnector -ProtocolLoggingLevel None
  - Confirm no more mail flow appearing in message tracking logs
    - Get-MessageTrackingLogs -Start (Get-Date).AddDates(-3)
    - $messages | Get-MessageTrackingLogs -Start (Get-Date).AddDates(-5) -ResultSize unlimited
    - $messages | Group-Object -Property:Sender | Select Name,Count | ft -auto
  - Confirm no more client access traffic in IIS logs
    - Path: C:\inetpub\logs\LogFiles
    - Filter for username by importing to Excel, Log Parser or Log Parser Studio

- Remove mailbox databases and public folders
  - Get-Mailbox -Database DB
  - Remove-MailboxDatabase DB
  - Remove-PublicFolderDatabase PF\_Name

- Verify OAB of new Exchange server is configured to existing OAB
  - Get-OfflineAddressBook

- Uninstall Exchange from Control Panel
