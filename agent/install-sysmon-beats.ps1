<#

.SYNOPSIS
This Powershell script installs and configures Microsoft Sysinternals Sysmon and Elastic Winlogbeat with the aim
of shipping network connection events to a centralized Redis server.

.DESCRIPTION
This script install Microsoft Sysinternals Sysmon and Elastic Winlogbeat to the Windows Program Files directory.
Sysmon is then configured to report network connections and Winlogbeat is configured to send connection logs to
the desired Redis server.

.PARAMETER RedisHost
The IP address or hostname of the Redis server to send connection logs.

.PARAMETER RedisPort
The port on which the Redis server is listening. Defaults to TCP 6379.

.PARAMETER RedisPassword
Warning: Insecure!
The password for the Redis server's default account. If RedisPassword is not specified,
the script will ask for the password at runtime. In order to avoid recording the Redis
password, consider editing this file. Change the line `[string]$RedisPassword="",` to
`[string]$RedisPassword="YOUR_ELASTIC_PASSWORD_HERE",`.

.PARAMETER SysmonConfig
Path or URL referring to a Sysmon configuration xml file. The configuration necessary to run Espy
will be merged with the given configuration, written to a new file, and registered with Sysmon.
If SysmonConfig is not provided, and Sysmon has already been installed, the installer will attempt to find the existing configuration file.
Otherwise, if SysmonConfig is not provided, and Sysmon has not already been installed, a default configuration file will be installed. 

The following changes are made to the given configuration file:
- EventFiltering NetworkConnect elements are updated to record every event
- EventFiltering DnsQuery elements are updated to record every event

The schema version of the given Sysmon configuration must be greater than version 4.1.

.PARAMETER BeatsVersion
The version of Winlogbeat to install. This will override any logic that handles upgrading to an
intermediate version of Winlogbeat before upgrading to a higher major version.

.EXAMPLE
# Asks for Redis authentication details at runtime
.\install-sysmon-beats.ps1 my-redis-host.com 6379

# Reads Redis authentication details from the command line aguments
.\install-sysmon-beats.ps1 my-redis-host.com 6379 redis_password

# Overrides the version of Winlogbeat to install
.\install-sysmon-beats.ps1 my-redis-host.com 6379 redis_password -BeatsVersion "8.6.2"


.NOTES
The Redis credentials are stored locally using Elastic Winlogbeat's secure
storage facilities. The RedisPassword should not be passed into the script
in a secure environment. Instead, either leave the credentials blank and
enter the credentials during the installation process, or edit the parameters' default values in the script.
#>

param (
  [Parameter(Mandatory = $true)][string]$RedisHost,
  [string]$RedisPort = "6379",
  [string]$RedisPassword = "",
  [string]$SysmonConfig = "",
  [string]$BeatsVersion = ""

)

$ELK_STACK_VERSION = "8.7.0"

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  # Use param values instead of $args because $args doesn't appear to get populated if param values are specified
  # Also set the ExecutionPolicy to Bypass otherwise this will likely fail as script
  # execution is disabled by default.
  $arguments = "-ExecutionPolicy", "Bypass", "-File", $myinvocation.mycommand.definition, $RedisHost, $RedisPort
  if ($RedisPassword) {
    # Only add this argument if the user provided it, otherwise it will be blank and will cause an error
    $arguments += $RedisPassword
  }
  if ($BeatsVersion) {
    # Only add this argument if the user provided it, otherwise it will be blank and will cause an error
    $arguments += "-BeatsVersion $BeatsVersion"
  }
  
  Start-Process -FilePath powershell -Verb runAs -ArgumentList $arguments
  Break
}

[bool] $OverrideBeatsVersion = $false
if ([string]::IsNullOrWhiteSpace("$BeatsVersion")) {
  $BeatsVersion = "$ELK_STACK_VERSION"
}
else {
  if ($null -eq ("$BeatsVersion" -as [System.Version])) {
    throw "Beats version $BeatsVersion is not a valid version, please provide a valid version number."
  }
  if ([System.Version]$BeatsVersion -lt [System.Version]"7.17.9") {
    throw "Minimum supported Beats version is 7.17.9, exiting"
  }
  $OverrideBeatsVersion = $true
}

# Check for existing winlogbeat installation via BeaKer
if (Test-Path "$Env:programfiles\Winlogbeat-BeaKer" -PathType Container) {
  Write-Output "Detected existing winlogbeat installation performed by BeaKer. Continuing the install may result in a partially working Sysmon/winlogbeat setup."
  $installAnyway = Read-Host -Prompt "Are you sure you want to continue? [y/n]"
  if (($installAnyway -eq 'n') -or ($installAnyway -eq 'N')) {
    Exit
  }
}

# Copy Sysmon into Program Files if it doesn't already exist
if (-not (Test-Path "$Env:programfiles\Sysmon" -PathType Container)) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -OutFile Sysmon.zip https://download.sysinternals.com/files/Sysmon.zip
  Expand-Archive .\Sysmon.zip
  rm .\Sysmon.zip
  mv .\Sysmon\ "$Env:programfiles"
}

# Set SysmonConfig by querying Sysmon if it has already been installed
if ($SysmonConfig -eq "" -and (Test-Path "$Env:windir\Sysmon64.exe" -PathType Leaf)) {
  $oldConfigPathLine = (& "$Env:windir\Sysmon64.exe" "-c" | Select-String " - Config file:").Line
  $oldConfigPath = [RegEx]::Matches($oldConfigPathLine, "^ - Config file:\s*(\S.*)$").Groups[1].Value  # Returns "" if no match
  if (Test-Path "$oldConfigPath" -PathType Leaf) {
    $SysmonConfig = (Resolve-Path "$oldConfigPath").Path
  }
  else {
    throw "Sysmon is already installed, but the existing Sysmon configuration file could not be found"
  }
}

if ($SysmonConfig -ne "" -and (Test-Path "$SysmonConfig" -PathType Leaf)) {
  [xml]$sysmonXML = $null

  $configPathAsURI = $sysmonConfig -as [System.URI]
  if ($null -ne $configPathAsURI.AbsoluteURI -and $configPathAsURI.Scheme -match '[http|https]') {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [xml]$sysmonXML = (Invoke-WebRequest -Uri "$SysmonConfig").Content
  }
  else {
    [xml]$sysmonXML = Get-Content "$SysmonConfig"
  } 

  $schemaVersionString = $sysmonXML.Sysmon.schemaversion

  if ($null -eq $schemaVersionString) {
    # can't read existing schema version
    throw "Could not read schema version from the provided Sysmon configuration file"
  }

  $schemaVersionParts = $schemaVersionString.Split(".")
  if ($schemaVersionParts.Length -ne 2) {
    # can't parse existing schema version
    throw "Could not parse schema version from the provided Sysmon configuration file"
  }

  if ($schemaVersionParts[0] -lt 4 -or $schemaVersionParts[0] -eq 4 -and $schemaVersionParts[1] -le 1) {
    # can't upgrade configs from Sysmon 8 and lower
    throw "The provided Sysmon configuration file is too old (schema version <= 4.1)"
  }

  if ($schemaVersionParts[0] -lt 4 -or $schemaVersionParts[0] -eq 4 -and $schemaVersionParts[1] -le 20) {
    Write-Output "Upgrading Sysmon schema version from $schemaVersionString to 4.22"
    $sysmonXML.Sysmon.schemaversion = "4.22"
  }

  if ($null -eq $sysmonXML.Sysmon.EventFiltering) {
    # the EventFiltering node must exist
    throw "The provided Sysmon configuration must define the EventFiltering section"
  }

  # Remove NetworkConnect nodes
  $networkConnectNodes = Select-Xml -Xpath "//Sysmon//NetworkConnect" -Xml $sysmonXML
  foreach ($node in $networkConnectNodes) {
    $node.Node.ParentNode.RemoveChild($node.Node) | Out-Null
  }

  $newNetworkConnectNode = $sysmonXML.CreateElement("NetworkConnect")
  $newNetworkConnectNode.SetAttribute("onmatch", "exclude")
  $sysmonXML.Sysmon.EventFiltering.AppendChild($newNetworkConnectNode) | Out-Null

  $dnsQueryNodes = Select-Xml -Xpath "//Sysmon//DnsQuery" -Xml $sysmonXML
  foreach ($node in $dnsQueryNodes) {
    $node.Node.ParentNode.RemoveChild($node.Node) | Out-Null
  }

  $newDnsQueryNode = $sysmonXML.CreateElement("DnsQuery")
  $newDnsQueryNode.SetAttribute("onmatch", "exclude")
  $sysmonXML.Sysmon.EventFiltering.AppendChild($newDnsQueryNode) | Out-Null
    
  Write-Output $sysmonXML.OuterXml > "$Env:programfiles\Sysmon\sysmon-espy.xml"
}
else {
  Write-Output @"
<Sysmon schemaversion="4.22">
    <HashAlgorithms>md5,sha256,IMPHASH</HashAlgorithms>
    <EventFiltering>
        <ProcessCreate onmatch="include">
            <!--SYSMON EVENT ID 1 : PROCESS CREATION [ProcessCreate]-->
        </ProcessCreate>

        <FileCreateTime onmatch="include">
            <!--SYSMON EVENT ID 2 : FILE CREATION TIME RETROACTIVELY CHANGED IN THE FILESYSTEM [FileCreateTime]-->
        </FileCreateTime>

        <NetworkConnect onmatch="exclude">
            <!--SYSMON EVENT ID 3 : NETWORK CONNECTION INITIATED [NetworkConnect]-->
        </NetworkConnect>

        <!--SYSMON EVENT ID 4 : RESERVED FOR SYSMON SERVICE STATUS MESSAGES-->

        <ProcessTerminate onmatch="include">
            <!--SYSMON EVENT ID 5 : PROCESS ENDED [ProcessTerminate]-->
        </ProcessTerminate>

        <DriverLoad onmatch="include">
            <!--SYSMON EVENT ID 6 : DRIVER LOADED INTO KERNEL [DriverLoad]-->
        </DriverLoad>

        <ImageLoad onmatch="include">
            <!--SYSMON EVENT ID 7 : DLL (IMAGE) LOADED BY PROCESS [ImageLoad]-->
        </ImageLoad>

        <CreateRemoteThread onmatch="include">
            <!--SYSMON EVENT ID 8 : REMOTE THREAD CREATED [CreateRemoteThread]-->
        </CreateRemoteThread>

        <RawAccessRead onmatch="include">
            <!--SYSMON EVENT ID 9 : RAW DISK ACCESS [RawAccessRead]-->
        </RawAccessRead>

        <ProcessAccess onmatch="include">
            <!--SYSMON EVENT ID 10 : INTER-PROCESS ACCESS [ProcessAccess]-->
        </ProcessAccess>

        <FileCreate onmatch="include">
            <!--SYSMON EVENT ID 11 : FILE CREATED [FileCreate]-->
        </FileCreate>

        <RegistryEvent onmatch="include">
            <!--SYSMON EVENT ID 12 & 13 & 14 : REGISTRY MODIFICATION [RegistryEvent]-->
        </RegistryEvent>

        <FileCreateStreamHash onmatch="include">
            <!--SYSMON EVENT ID 15 : ALTERNATE DATA STREAM CREATED [FileCreateStreamHash]-->
        </FileCreateStreamHash>

        <!--SYSMON EVENT ID 16 : SYSMON CONFIGURATION CHANGE-->

        <PipeEvent onmatch="include">
            <!--SYSMON EVENT ID 17 & 18 : PIPE CREATED / PIPE CONNECTED [PipeEvent]-->
        </PipeEvent>

        <WmiEvent onmatch="include">
            <!--SYSMON EVENT ID 19 & 20 & 21 : WMI EVENT MONITORING [WmiEvent]-->
        </WmiEvent>

        <DnsQuery onmatch="exclude">
            <!--SYSMON EVENT ID 22 : DNS QUERY MONITORING [DnsQuery]-->
        </DnsQuery>

        <!--SYSMON EVENT ID 255 : ERROR-->
    </EventFiltering>
</Sysmon>
"@ > "$Env:programfiles\Sysmon\sysmon-espy.xml"
}

# Load the new sysmon configuration and install the service if needed
if (Test-Path "$Env:windir\Sysmon64.exe" -PathType Leaf) {
  & "$Env:programfiles\Sysmon\Sysmon64.exe" -c "$Env:programfiles\Sysmon\sysmon-espy.xml"
}
else {
  & "$Env:programfiles\Sysmon\Sysmon64.exe" -accepteula -i "$Env:programfiles\Sysmon\sysmon-espy.xml"
}

$InstalledBeatsVersion = ""
[bool] $DownloadWinlogbeat = $false

# Check for fresh install or pre-7.17 install
if (-not (Test-Path "$Env:programfiles\Winlogbeat-Espy\winlogbeat.exe" -PathType Leaf)) {
  $DownloadWinlogbeat = $true
  
  # Create install directory if it doesn't exist
  if (-not (Test-Path "$Env:programfiles\Winlogbeat-Espy" -PathType Container)) {
    mkdir "$Env:programfiles\Winlogbeat-Espy" > $null
  }
  
  # Check if this is a pre-7.17 upgrade install
  if ((Test-Path "$Env:programfiles\winlogbeat-7*" -PathType Container)) {
    ### Make sure that Beats is upgraded to 7.17 before installing v8.x
    # Install winlogbeat 7.17.9 if the current version is less than 8.x
    if (!$OverrideBeatsVersion) {
      $BeatsVersion = "7.17.9"
    }
    Copy-Item "$Env:programfiles\winlogbeat-7*\winlogbeat.yml" "$Env:programfiles\Winlogbeat-Espy"
  }
}
else {
  # Check if currently installed version is outdated
  $InstalledBeatsVersion = (& "$Env:programfiles\Winlogbeat-Espy\winlogbeat.exe" version | Select-String -Pattern "(?<=winlogbeat version )(\d+\.\d+\.\d+)").Matches.Value
  if ($null -eq ("$InstalledBeatsVersion" -as [System.Version])) {
  
    if (!$OverrideBeatsVersion) {
      throw "Unable to retrieve installed winlogbeat version"
    }
    else {
      Write-Output "Unable to retrieve installed winlogbeat version, continuing anyway"
      $DownloadWinlogbeat = $true
    }
  }
  else {
    if ([System.Version]"$InstalledBeatsVersion" -lt [System.Version]"$BeatsVersion") {
      $DownloadWinlogbeat = $true
    }
  }
}

# Download winlogbeat and move it to install directory
if ($DownloadWinlogbeat) {
  Write-Output "######## Downloading winlogbeat version $BeatsVersion ########"

  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -OutFile WinLogBeat.zip https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-"$BeatsVersion"-windows-x86_64.zip
  Expand-Archive .\WinLogBeat.zip
  rm .\WinLogBeat.zip
  rm .\WinLogBeat\winlogbeat*\winlogbeat.yml

  # Stop winlogbeat service if it exists 
  if (Get-Service winlogbeat -ErrorAction SilentlyContinue) {
    Stop-Service winlogbeat
    (Get-Service winlogbeat).WaitForStatus('Stopped')
    Start-Sleep -s 1
  }
  Copy-Item -Path .\WinLogBeat\winlogbeat*\* -Destination "$Env:programfiles\Winlogbeat-Espy\" -Recurse -Force
  rm .\Winlogbeat -Recurse
}

Write-Output "######## Installing winlogbeat version $BeatsVersion ########"

# Begin winlogbeat configuration
Set-Location "$Env:programfiles\Winlogbeat-Espy\"

# Backup winlogbeat config if it exists
if (Test-Path -PathType Leaf .\winlogbeat.yml) {
  if ($DownloadWinlogbeat) {
    # Backup config with its version in the name if upgrading to a new Beats version
    # so that the config isn't overwritten by subsequent upgrades. This is useful in case
    # breaking changes between configurations need to be referenced in the future for troubleshooting
    Copy-Item .\winlogbeat.yml .\winlogbeat-$InstalledBeatsVersion-old.yml.bak
  }
  else {
    Copy-Item .\winlogbeat.yml .\winlogbeat.yml.bak
  }
}

$winlogbeatSysmonCfg = ""

if ([System.Version]$BeatsVersion -lt [System.Version]"8.0.0") {
  $winlogbeatSysmonCfg = @"
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
    event_id: 3, 22
    processors:
      - script:
          lang: javascript
          id: sysmon
          file: ${path.home}/module/sysmon/config/winlogbeat-sysmon.js
      - add_host_metadata:
          netinfo:
            enabled: true
"@
}
else {
  $winlogbeatSysmonCfg = @"
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
    event_id: 3, 22
"@
}

# Add the windows event logs config to winlogbeat if it doesn't exist.
if ((Test-Path -PathType Leaf .\winlogbeat.yml) -and 
    ((Get-Content -Raw .\winlogbeat.yml | Select-String "winlogbeat\.event_logs:").Matches.Length -gt 0)) {

  # Attempt to remove the "- script" entry that points to winlogbeat-sysmon.js if installing v8.x
  # Starting winlogbeat with this entry in the config on v8.x will fail
  if (([System.Version]$BeatsVersion -ge [System.Version]"8.0.0") -and 
      ((Get-Content -Raw .\winlogbeat.yml | Select-String "winlogbeat-sysmon.js").Matches.Length -gt 0)) {
    
    # Find "- script" entries
    $scriptEntries = Get-Content .\winlogbeat.yml | Select-String "- script" | Select-Object LineNumber

    foreach ($match in $scriptEntries) {
      $endLine = $match.LineNumber + 3
    
      $scriptBlock = @() # array to hold the lines in the script block

      [bool] $isMatch = $false

      # Look through each line in the block and verify that it contains winlogbeat-sysmon.js
      for (($i = $match.LineNumber); $i -ile $endLine; $i++) {
        $line = Get-Content .\winlogbeat.yml | Select -First 1 -Skip ($i - 1)
        $scriptBlock += $line
        if (($line | Select-String "winlogbeat-sysmon.js").Matches.Length -gt 0) {
          $isMatch = $true
        }
      }
      if ($isMatch) {
        # Diff between the full config file and the script block
        # Replace the config with the script block removed
        Compare-Object (Get-Content .\winlogbeat.yml) $scriptBlock | Select-Object -ExpandProperty InputObject | Set-Content .\winlogbeat.yml
      }
    }
  }
  else {
    Write-Output "Found Event Logs stanza in the existing winlogbeat configuration"
    Write-Output "Refusing to update winlogbeat Event Logs configuration"
    Write-Output "Please ensure the following configuration is present in`n`t$( (Resolve-Path .).Path )\winlogbeat.yml:"
    Write-Output ""
    Write-Output "$winlogbeatSysmonCfg"
    Write-Output ""
  }
}
else {
  Write-Output "" >> .\winlogbeat.yml
  Write-Output "$winlogbeatSysmonCfg" >> .\winlogbeat.yml
}

$winlogbeatRedisCfg = @"
output.redis:
  hosts:
    - ${RedisHost}:${RedisPort}
  ssl:
    enabled: true
    verification_mode: none
    supported-protocols: [TLSv1.2, TLSv1.3]
  key: "net-data:sysmon"
  password: `"`${REDIS_PASSWORD}`"
"@

if ((Test-Path -PathType Leaf .\winlogbeat.yml) -and 
    ((Get-Content -Raw .\winlogbeat.yml | Select-String "output\.redis:").Matches.Length -gt 0)) {
  Write-Output "Found Redis stanza in the existing winlogbeat configuration"
  Write-Output "Refusing to update winlogbeat Redis configuration"
  Write-Output "Please ensure the following configuration is present in`n`t$( (Resolve-Path .).Path )\winlogbeat.yml:"
  Write-Output ""
  Write-Output "$winlogbeatRedisCfg"
  Write-Output ""
}
else {
  Write-Output "" >> .\winlogbeat.yml
  Write-Output "$winlogbeatRedisCfg" >> .\winlogbeat.yml
}

# Create the keystore if it doesn't exist
if (-not (Test-Path -PathType Leaf "$Env:ProgramData\winlogbeat\winlogbeat.keystore")) {
  .\winlogbeat.exe --path.data "$Env:ProgramData\winlogbeat" keystore create
  # Set ACL's of the $Env:ProgramData\winlogbeat folder to be the same as $Env:ProgramFiles\winlogbeat* (the main install path)
  # This helps ensure that "normal" users aren't able to access the $Env:ProgramData\winlogbeat folder
  Get-ACL -Path "$Env:ProgramFiles\Winlogbeat-Espy\" | Set-ACL -Path "$Env:ProgramData\winlogbeat"
}

# Set the Redis password if it doesn't exist
if ((.\winlogbeat.exe --path.data "$Env:ProgramData\winlogbeat" keystore list | Select-String REDIS_PASSWORD).Matches.Length -eq 0) {
  if ($RedisPassword) {
    Write-Output "$RedisPassword" | .\winlogbeat.exe --path.data "$Env:ProgramData\winlogbeat" keystore add REDIS_PASSWORD --stdin
  }
  else {
    .\winlogbeat.exe --path.data "$Env:ProgramData\winlogbeat" keystore add REDIS_PASSWORD
  }
}

PowerShell.exe -ExecutionPolicy UnRestricted -File .\install-service-winlogbeat.ps1
Start-Service winlogbeat
