# Inventorying Existing Environment

- List existing Exchange servers in the environment
  - Get-ExchangeServer | ft Name, Edition, AdminDisplayVersion, ProductId, IsExchangeTrialEdition |  ft -autosize -wrap
  - Get-Command ExSetup | ForEach {$_.FileVersionInfo}

- Have an estimation of how many mailboxes on each existing Exchange server
  - Get-Mailbox -ResultSize Unlimited | Group-Object -Property:Database | Select Name,Count | ft -auto

- Collect AD forest functional level info
  - Get-ADForest

- Collect domain controller version in AD
  - Get-ADDomainController | Select Name, OperatingSystem

- Client Access Namespace (used by client to connect to Exchange)
  - Inventory PowerShell – Collect internal and external domain names for each of the below
    - Autodiscover (SCP)
      - Get-ClientAccessServer | Select Identity,AutoDiscoverServiceInternalUri
    - Outlook Anywhere (RPC over HTTP)
      - Get-OutlookAnywhere -ADPropertiesOnly | Select Identity,Internalhostname,Externalhostname | ft -wrap
      - Get-OutlookAnywhere -ADPropertiesOnly | Select Identity, \*Auth\*, \*SSL\*, MetabasePath | fl
      - If Exchange 2010 is in the environment, check if Outlook Anywhere is enabled (required for coexistence)
        - Get-ExchangeServer | Where {($_.AdminDisplayVersion -Like "Version 14*") -And ($_.ServerRole -Like "*ClientAccess*")} | Get-ClientAccessServer | Select Name,OutlookAnywhereEnabled
    - OWA
      - Get-OWAVirtualDirectory -ADPropertiesOnly | Select Identity,InternalURL,ExternalURL | ft -wrap
      - Get-OWAVirtualDirectory -ADPropertiesOnly | Select Identity,\*Auth\* | fl
    - ECP
      - Get-ECPVirtualDirectory -ADPropertiesOnly | Select Identity,InternalURL,ExternalURL | ft -wrap
      - Get-ECPVirtualDirectory -ADPropertiesOnly | Select Identity,\*Auth\* | fl
    - Offline Address Book (OAB)
      - Get-OABVirtualDirectory -ADPropertiesOnly | Select Identity,InternalURL,ExternalURL | ft -wrap
      - Get-OABVirtualDirectory -ADPropertiesOnly | Select Identity,\*Auth\* | fl
    - Exchange Web Services (EWS)
      - Get-WebServicesVirtualDirectory -ADPropertiesOnly | Select Identity,InternalURL,ExternalURL | ft -wrap
      - Get-WebServicesVirtualDirectory -ADPropertiesOnly | Select Identity,\*Auth\* | fl
    - MAPI/HTTP
      - Get-MAPIVirtualDirectory -ADPropertiesOnly | Select Identity,InternalURL,ExternalURL | ft -wrap
      - Get-MAPIVirtualDirectory -ADPropertiesOnly | Select Identity,\*Auth\* | fl
    - ActiveSync
      - Get-ActiveSyncVirtualDirectory -ADPropertiesOnly | Select Identity,InternalURL,ExternalURL | ft -wrap
      - Get-ActiveSyncVirtualDirectory -ADPropertiesOnly | Select Identity,\*Auth\* | fl
    - PowerShell
      - Get-PowerShellVirtualDirectory -ADPropertiesOnly | Select Identity,InternalURL,ExternalURL | ft -wrap
      - Get-PowerShellVirtualDirectory -ADPropertiesOnly | Select Identity,\*Auth\* | fl
      - Related error: Unlike other virtual directories, for the PowerShell one, it should remain configured with namespaces (URLs) that match the server's FQDN, which is the default setting. Otherwise, errors like below may be produced with remote administration utilities:
        > Connecting to remote server mail.company.com failed with the following error message : WinRM cannot process the request. The following error occurred while using Kerberos authentication: Cannot find the computer mail.company.com. Verify that the computer exists on the network and that the name provided is spelled correctly. For more information, see the about_Remote_Troubleshooting Help topic.
        
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
      - Get-ExchangeCertificate -Thumbprint &lt;From\_Above\_Command&gt; | fl
    - Take note of IMAP and POP3 X509CertificateName parameter from each responsible server which could cause warning of mismatch when enabling certificate for IMAP and POP3 later
      - Get-IMAPSettings
      - Get-IMAPSettings -Server <Server_Name>
      - Get-POPSettings
      - Get-POPSettings -Server <Server_Name>
- Mailbox Storage Quotas
  - Beware of default mailbox quota – For Exchange 2016, it is 2GB by default
    - Mailbox migration fails if size exceeds target database
    - New databases should be configured with the same or larger quotas
  - Inventory PowerShell (second command supports querying Exchange 2010, if exists, from newer Exchange Management Shell)
    - Get-MailboxDatabase | Select Name,\*Quota\*
    - Get-MailboxDatabase -IncludePreExchange2013| Select Name,\*Quota\*

- Email Routing Topology and Transport
  - Internal mail flow between supported Exchange servers (Exchange 2010 &lt;&gt; 2013 &lt;&gt; 2016) is automatic (no further configuration required)
  - Inbound mail flow from the Internet
    - Acquire internal DNS MX record:
      - Resolve-DnsName -Type MX -Name company.com -Server &lt;internal\_DNS&gt;
      - Resolve-DnsName -Type A  -Name mail.company.com -Server &lt;internal\_DNS&gt;
    - Alternatively
      - nslookup -&gt; server internal\_DNS\_Server -&gt; set type=MX -&gt; company.com
      - nslookup -&gt; server internal\_DNS\_Server -&gt; set type=A -&gt; mail.company.com
    - Acquire external DNS MX and A record (or using [www.mxtoolbox.com](www.mxtoolbox.com)):
      - Resolve-DnsName -Type MX -Name company.com -Server 8.8.8.8
      - Resolve-DnsName -Type A -Name mail.company.com -Server 8.8.8.8
    - Alternatively
      - nslookup -&gt; server 8.8.8.8 -&gt; set type=MX -&gt; company.com
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
  - Once found out, look for the remote IP Ranges of it (i.e. IP addresses which are allowed to relay email via that Exchange server and other settings
    - Get-ReceiveConnector &quot;Server\_Name\Receive\_Connector\_Name&quot; | fl Name, Server, Enabled, Bindings, TransportRole, RemoteIPRanges, PermissionGroups
    - Get-ReceiveConnector -Identity &quot;Server\_Name\Receive\_Connector\_Name&quot; | Get-ADPermission
  - Once an IP address is acquired, perform PTR DNS lookup using nslookup to find out its hostname/FQDN
    - nslookup &lt;IP\_address&gt;

- Maximum allowed message size of Receive Connector
  - Get-ReceiveConnector | Select Identity, MaxMessageSize

- Public Folders
  - Inventorying existing public folders and existing Exchange Server
    - Get-PublicFolder -Recurse | Export-Clixml C:\PFMigration\Legacy\_PFStructure.xml
  - Acquire existing pubic folder statistics
    - Get-PublicFolderStatistics | Export-Clixml C:\PFMigration\Legacy\_PFStatistics.xml
  - Acquire public folder permissions
    - Get-PublicFolder -Recurse | Get-PublicFolderClientPermission | Select Identity, User -ExpandProperty AccessRights | Export-Clixml C:\PFMigration\Legacy\_PFperms.xml
  - Check if existing public folder names have backslash character which is invalid
    - Get-PublicFolderStatistics -ResultSize Unlimited | Where {$\_.Name -Like &quot;\*\\*&quot;} | fl name,identity
  - Watch out for existing pubic folder migration job
    - Get-OrganizationConfig | fl PublicFoldersLockedforMigration,PublicFolderMigrationComplete

- Other
  - Collect information on arbitration mailboxes
    - Set-ADServerSettings -ViewEntireForest:$true
    - Get-Mailbox -Arbitration | Select name,database
  - Check whether Outlook Anywhere is enabled (on all servers)
    - Get-ClientAccessServer | Select Name,OutlookAnywhereEnabled
  - Check organization config e.g. whether MAPI over HTTP is enabled per [Microsoft Docs](https://docs.microsoft.com/en-us/exchange/clients/mapi-over-http/configure-mapi-over-http?view=exchserver-2016)
    - Get-OrganizationConfig
    - Get-OrganizationConfig | fl *mapi*
  - Check CAS mailbox e.g. whether OWA, ActiveSync, POP3, IMAP, MAPI over HTTP, etc. is enabled per mailbox
    - Get-CasMailbox -ResultSize Unlimited
    - Get-CasMailbox -ResultSize Unlimited | ft name, *mapi*
  - Outlook Address Book configuration
    - Get-OfflineAddressBook
    - Get-OfflineAddressBook | fl name,virtual*,guid,global*

# Basic Health Checking

- Check service health
  - Test-ServiceHealth
- Get a count of current email messages in mail queue on Hub Transport servers
  - Get-Queue
- Check MAPI Connectivity
  - Test-MAPIConnectivity
- Validates that the RPC/HTTP endpoint is able to receive traffic on the Mailbox server
  - Test-OutlookConnectivity -ProbeIdentity "OutlookRpcSelfTestProbe"
- Validates that the MAPI/HTTP endpoint is able to receive traffic on the Mailbox server
  - Test-OutlookConnectivity -ProbeIdentity "OutlookMapiHttpSelfTestProbe"
- Check replication status of all mailbox databases (for non-standalone, DAG scenario)
  - Get-MailboxDatabaseCopyStatus \*\\\*
  - Get-MailboxDatabaseCopyStatus \*\\\* | select name, *activ* | ft
- Check whether replication status is healthy
  - Test-ReplicationHealth
- Check server component state
  - Get-ExchangeServer | Get-ServerComponentState | ft -wrap -autosize
- Run additional third-party health checking scripts as required, [for example](https://practical365.com/exchange-server/powershell-script-exchange-server-health-check-report/)
  - Test-ExchangeServerHealth.ps1 -ReportMode -Log

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

# Installing Exchange

Note: For this section, it is recommended to also check [Microsoft Docs](https://docs.microsoft.com/en-us/exchange/plan-and-deploy/prerequisites?view=exchserver-2016) for the latest prerequisites.

1. Privileges of account used during setup
    - Domain Admin, Enterprise Admin and Schema Admin
2. Confirm PowerShell v4.0 is available
3. Confirm .NET Framework 4.8 is available (required for both mailbox and Edge servers)
4. Confirm Microsoft KB 3206632 is available
5. Confirm Visual C++ Redistributable for Visual Studio 2012 Update 4 (required for both mailbox and Edge servers) is available
6. Confirm Visual C++ 2013 Redistributable Package is available
7. Confirm Windows components and Unified Communications Managed API 4.0 Core Runtime 64-bit are installed
   - Acquire the PowerShell command (Install-WindowsFeature…) to install Windows components from [https://technet.microsoft.com/en-us/library/bb691354%28v=exchg.160%29.aspx](https://docs.microsoft.com/en-us/Exchange/plan-and-deploy/prerequisites?redirectedfrom=MSDN&view=exchserver-2016)
8. Perform schema extensions (not required if `/PrepareAD` is run)
    - setup /PrepareSchema /IAcceptExchangeServerLicenseTerms
9. Perform Active Directory preparation
    - setup /PrepareAD /IAcceptExchangeServerLicenseTerms
10. Perform domain preparation (only required if there are multiple domains)
    - setup /PrepareAllDomains /IAcceptExchangeServerLicenseTerms
11.  Install product key
    - Set-ExchangeServer <Server_Name> -ProductKey xxxxx-xxxxx-xxxxx-xxxxx-xxxxx

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
      - Set-ClientAccessServer -Identity EXCH16 -AutoDiscoverServiceInternalUri [https://mail.company.com/Autodiscover/Autodiscover.xml](https://mail.company.com/Autodiscover/Autodiscover.xml)
    - Ignore the AutoDiscover virtual directory setting which is not used for AutoDiscover – only SCP is used for AutoDiscover in an internal environment
  - IMAP
    - Internal proxying may have problem with IMAP when proxying from Exchange 2016 to Exchange 2010 in a mixed exchange 2010-2016 coexistence setup, in which a mailbox which is hosted on the Exchange 2010 server cannot be opened when connecting through the Exchange 2016 servers, while opening a mailbox with IMAP on Exchange 2010 or Exchange 2016 directly is OK
    - To solve it, Set EnableGSSAPIAndNTLMAuth to false on new Exchange 2016 servers
      - Set-ImapSettings -EnableGSSAPIAndNTLMAuth:$false
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
      - Do this ASAP to prevent clients from connecting to server which prompts below certificate error in Outlook desktop client
      > server_name.domain_name
      > Information you exchange with this site cannot be viewed or changed by others. However, there is a problem with the site's security certificate.
      > X The security certificate was issued by a company you have not chosen to trust, View the certificate to determine whether you want to trust the certifying authority
      > ✔ The security certificate date is valid. 
      > ✔ The security certificate has a valid name.
      > Do you want to proceed?
    - Import from existing server to new server
      - In MMC Console, add Certificates snap-in, select Computer account (Local Computer), then import the private key (.pfx) under Personal > Certificates folder
      - Related error: If this is not done, Outlook users may receive an error prompt due to the self-signed certificate being used:
          > There is a problem with the proxy server's security certificate. The security certificate is not from a trusted certifying authority.
          Outlook is unable to connect to the proxy server [servername] (Error Code 8).
    - Enable it for SMTP and IIS
      - `Enable-ExchangeCertificate -Server <Server_Name> -Thumbprint <Thumbprint_acquired_from_Get-ExchangeCertificate> -Services SMTP,IIS`
    - Enable it for IMAP and POP3, configure X509CertificateName of IMAP and POP3 settings accordingly to prevent errors enabling
      - `Set-IMAPSettings -Server <Server_Name> -X509CertificateName mail.company.com`
      - `Set-POPSettings -Server <Server_Name> -X509CertificateName mail.company.com`
      - `Restart-Service <MSExchangePOP3>`
      - `Restart-Service <MSExchangeIMAP4>`
      - `Enable-ExchangeCertificate -Server <Server_Name> -Thumbprint <Thumbprint_acquired_from_Get-ExchangeCertificate> -Services POP,IMAP`
3. Configure the client access namespaces
    - Configure each HTTPS service with the same namespace as existing servers (virtual directories)
      - Defining variables
        - $InternalHostname = "mail.company.com"
        - $ExternalHostname = "mail.company.com"
        - $Server = "EXCH16"
      - Outlook Anywhere
        - Get-OutlookAnywhere -Server $Server | Set-OutlookAnywhere -ExternalHostname $ExternalHostname -InternalHostname $InternalHostname -ExternalClientsRequireSsl $True -InternalClientsRequireSSL $true -DefaultAuthenticationMethod NTLM
      - OWA Virtual Directory
        - Get-OWAVirtualDirectory -Server $Server | Set-OWAVirtualDirectory -ExternalUrl https://$ExternalHostname/owa -InternalUrl https://$InternalHostname/owa
      - ECP Virtual Directory
        - Get-EcpVirtualDirectory -Server $Server | Set-EcpVirtualDirectory -ExternalUrl https://$ExternalHostname/ecp -InternalUrl https://$InternalHostname/ecp
      - ActiveSync Virtual Directory
        - Get-ActiveSyncVirtualDirectory -Server $Server | Set-ActiveSyncVirtualDirectory -ExternalUrl https://$ExternalHostname/Microsoft-Server-ActiveSync -InternalUrl https://$InternalHostname/Microsoft-Server-ActiveSync
      - EWS (Exchange Web Services) Virtual Directory
        - Get-WebServicesVirtualDirectory -Server $Server | Set-WebServicesVirtualDirectory -ExternalUrl https://$ExternalHostname/EWS/Exchange.asmx -InternalUrl https://$InternalHostname/EWS/Exchange.asmx
      - OAB (Offline Address Book) Virtual Directory
        - Get-OabVirtualDirectory -Server $Server | Set-OabVirtualDirectory -ExternalUrl https://$ExternalHostname/OAB -InternalUrl https://$InternalHostname/OAB
      - MAPI Virtual Directory
        - Get-MapiVirtualDirectory -Server $Server | Set-MapiVirtualDirectory -ExternalUrl https://$ExternalHostname/mapi -InternalUrl -InternalUrl https://$InternalHostname/mapi
      - Note: These changes do not make client connect to new Exchange server immediately; client will still connect to where DNS is resolving the namespace
    - Ensure new Exchange server uses existing authentication (e.g. form-based authentication with the same logon format)
    - Special concerns for Exchange 2010
      - Outlook Anywhere must be enabled
      - Check whether Outlook Anywhere is enabled
        - Get-ExchangeServer | Where {($\_.AdminDisplayVersion -Like &quot;Version 14\*&quot;) -And ($\_.ServerRole -Like &quot;\*ClientAccess\*&quot;)} | Get-ClientAccessServer | Select Name,OutlookAnywhereEnabled
    - Enable Outlook Anywhere and configure IIS authentication (required for co-existence) with existing Exchange 2010 (CAS)
      - Get-ExchangeServer | Where {($\_.AdminDisplayVersion -Like &quot;Version 14\*&quot;) -And ($\_.ServerRole -Like &quot;\*ClientAccess\*&quot;)} | Get-ClientAccessServer | Where {$\_.OutlookAnywhereEnabled -Eq $False} | Enable-OutlookAnywhere -ClientAuthenticationMethod Basic -SSLOffloading $False -ExternalHostName $hostname -IISAuthenticationMethods NTLM, Basic
4. Test the namespaces
    - Before DNS change (risky), use a hosts file for testing with a pilot group
      - Content of hosts file:
        - IP\_Address\_of\_Exchange\_2016 mail.company.com
5. Cutover namespaces to Exchange 2016
    - Lower DNS TTL to 1 minute (done earlier than what the TTL specifies)
    - Make DNS change for internal client (e.g. AD DNS server)
    - Make firewall change for external client (NAT settings)
6. New Exchange server is in production for client connectivity now
7. Test using exrca &gt; Exchange Server &gt; Microsoft Outlook Connectivity Tests &gt; Outlook Connectivity
    - Usual to see a few failed Autodiscover items, as long as the overall Autodiscover is successful

# Migrating Mail Flow

- Internal mail flow between Exchange servers
  - Change required: no need further setup (automatically established between installed Exchange servers)
  - Common issue: maximum allowed message size setting differs among Exchange servers
  - Compare using PowerShell the MaxMessageSize values among different servers
    - Get-ReceiveConnector | Select Identity,MaxMessageSize
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
    - Related error: Be sure to check firewall and/or smart host (if in use) for settings required to enable newly introduced Exchange servers to relay email messages; other users using new servers to send emails (as part of being in the Source Server setting of Exchange Send Connector) may receive bounce-back messages with 550 error.
      > Generating server: <New_Exchange_Server>. Remote Server returned '550 Relay not permitted'
  - Analyze mail routing by pasting email header into exrca &gt; Message Analyzer

- Devices and applications that use SMTP relay
  - Change required
  - EAC &gt; Mail Flow &gt; New Receive Connector
    - General tab
      - Name: Provide a name for a new relay connector, e.g. Relay EXCH16
      - Role: Frontend Transport
      - Type: Custom
      - Edit remote network settings by removing default 0.0.0.0-255.255.255.255 and adding IP addresses of devices and applications which send via this relay connector
        - New-ReceiveConnector -Name "Relay EXCH16" -Server &lt;Server_Name&gt; -TransportRole FrontendTransport -Custom -Bindings 0.0.0.0:25 -RemoteIpRanges &lt;RemoteIPAddresses&gt;
    - Security tab
      - Tick &quot;Anonymous users&quot; under permission groups (leave all else unchecked except the first checkbox of TLS authentication)
        - Set-ReceiveConnector -Identity &quot;SERVER\Relay EXCH16&quot; -PermissionGroups AnonymousUsers
  - Allow Exchange relay connector to relay email sent to external recipient
    - Get-ReceiveConnector &quot;EXCH16\Relay EXCH16&quot; | Add-ADPermission -User &#39;NT Authority\Anonymous Logon&#39; -ExtendedRights MS-Exch-SMTP-Accept-Any-Recipient
  - Fix existing misconfiguration on devices and applications (if any)
  - DNS alias should exist for SMTP, e.g. smtp.company.com
  - Devices and applications should be using DNS alias instead of the hostname or IP address of the server
  - Take the chance of migration to fix any non-optimal settings

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
    - Check if existing public folder names have backslash character which is invalid
      - Get-PublicFolderStatistics -ResultSize Unlimited | Where {$\_.Name -Like &quot;\*\\*&quot;} | fl name,identity
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
      - Fix it by matching the quota of new server with that of the existing one
        - Get-MailboxDatabase -Server EXCH16 | Set-MailboxDatabase -IssueWarningQuota 5GB -ProhibitSendQuota 6GB -ProhibitSendReceiveQuota 10GB -CalendarLoggingQuota Unlimited
    - Common Issue: Outlook Address Book not configured on existing Exchange servers
      - Check
        - Get-OfflineAddressBook
      - Fix it by letting the new server use the OAB of the existing server
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
  3. Migrate arbitration mailboxes first (it is recommended to move all arbitration mailboxes to the latest version of Exchange [as soon as possible](https://blog.rmilne.ca/2016/09/15/when-to-move-arbitration-mailboxes/), after verifying the health of the latest installation. Do not migrate user mailboxes until it is done.)
      - Check
        - Set-ADServerSettings -ViewEntireForest:$true
        - Get-Mailbox -Arbitration | Select name,database
      - Do
        - Get-Mailbox -Arbitration &lt;Legacy_Database_Name&gt; | New-MoveRequest -TargetDatabase &lt;Target Database&gt;
      - Verify
        - Get-MoveRequest
        - Get-MoveRequest | Get-MoveRequestStatistics
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

# Techniques

- Start PowerShell Logging (append mode)
  - Start-Transcript transcript.log -Append
- Stop PowerShell Logging
  - Stop-Transcript
- Add Exchange PowerShell Snap-in (for launching Exchange Management Shell from standard PowerShell prompt)
  - Add-PsSnapin *exch*
- Connect to Other Exchange Servers
  - Connect-ExchangeServer MBX01 -ClientApplication:ManagementShell
- Invoke standard PowerShell commands on remote computers using PowerShell Remoting
  - Invoke-Command -ComputerName MBX01,MBX02 -ScriptBlock {Restart-Service -ServiceName MSExchangeIS}
