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

.EXAMPLE
# Asks for Redis authentication details at runtime
.\install-sysmon-beats.ps1 my-redis-host.com 6379

# Reads Redis authentication details from the command line aguments
.\install-sysmon-beats.ps1 my-redis-host.com 6379 redis_password

.NOTES
The Redis credentials are stored locally using Elastic Winlogbeat's secure
storage facilities. The RedisPassword should not be passed into the script
in a secure environment. Instead, either leave the credentials blank and
enter the credentials during the installation process, or edit the parameters' default values in the script.
#>

param (
    [Parameter(Mandatory=$true)][string]$RedisHost,
    [string]$RedisPort="6379",
    [string]$RedisPassword="",
    [string]$SysmonConfig=""
)

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    # Use param values instead of $args because $args doesn't appear to get populated if param values are specified
    # Also set the ExecutionPolicy to Bypass otherwise this will likely fail as script
    # execution is disabled by default.
    $arguments = "-ExecutionPolicy", "Bypass", "-File", $myinvocation.mycommand.definition, $RedisHost, $RedisPort
    if($RedisPassword) 
    {
        # Only add this argument if the user provided it, otherwise it will be blank and will cause an error
        $arguments += $RedisPassword
    }
  
    Start-Process -FilePath powershell -Verb runAs -ArgumentList $arguments
    Break
}

# Set SysmonConfig by querying Sysmon if it has already been installed
if ($SysmonConfig -eq "" -and (Test-Path "$Env:windir\Sysmon64.exe" -PathType Leaf)) {
    $oldConfigPathLine = (& "$Env:windir\Sysmon64.exe" "-c" | Select-String " - Config file:").Line
    $oldConfigPath = [RegEx]::Matches($oldConfigPathLine, "^ - Config file:\s*(\S.*)$").Groups[1].Value  # Returns "" if no match
    if (Test-Path "$oldConfigPath" -PathType Leaf) {
        $SysmonConfig = (Resolve-Path "$oldConfigPath").Path
    } else {
        throw "Sysmon is already installed, but the existing Sysmon configuration file could not be found"
    }
}

if ($SysmonConfig -ne "" -and (Test-Path "$SysmonConfig" -PathType Leaf)) {
    [xml]$sysmonXML = $null

    $configPathAsURI =$sysmonConfig -as [System.URI]
    if ($null -ne $configPathAsURI.AbsoluteURI -and $configPathAsURI.Scheme -match '[http|https]') {
        [xml]$sysmonXML = (Invoke-WebRequest -Uri "$SysmonConfig").Content
    } else {
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
} else {
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

        <DnsQuery onmatch="include">
            <!--SYSMON EVENT ID 19 & 20 & 21 : WMI EVENT MONITORING [WmiEvent]-->
        </DnsQuery>

        <!--SYSMON EVENT ID 255 : ERROR-->
    </EventFiltering>
</Sysmon>
"@ > "$Env:programfiles\Sysmon\sysmon-espy.xml"
}

# Copy Sysmon into Program Files if it doesn't already exist
if (-not (Test-Path "$Env:programfiles\Sysmon" -PathType Container)) {
    Invoke-WebRequest -OutFile Sysmon.zip https://download.sysinternals.com/files/Sysmon.zip
    Expand-Archive .\Sysmon.zip
    rm .\Sysmon.zip
    mv .\Sysmon\ "$Env:programfiles"
}

# Load the new sysmon configuration and install the service if needed
if (Test-Path "$Env:windir\Sysmon64.exe" -PathType Leaf) {
    & "$Env:programfiles\Sysmon\Sysmon64.exe" -c "$Env:programfiles\Sysmon\sysmon-espy.xml"
} else {
    & "$Env:programfiles\Sysmon\Sysmon64.exe" -accepteula -i "$Env:programfiles\Sysmon\sysmon-espy.xml"
}

# Download winlogbeat if it doesn't exist
if (-not (Test-Path "$Env:programfiles\winlogbeat*" -PathType Container)) {
  Invoke-WebRequest -OutFile WinLogBeat.zip https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-7.5.2-windows-x86_64.zip
  Expand-Archive .\WinLogBeat.zip
  rm .\WinLogBeat.zip
  mv .\WinLogBeat\winlogbeat* "$Env:programfiles"
}

# Begin winlogbeat configuration
Set-Location "$Env:programfiles\winlogbeat*\"

# Create the keystore if it doesn't exist
if (-not (Test-Path -PathType Leaf "C:\ProgramData\winlogbeat\winlogbeat.keystore")) {
    .\winlogbeat.exe --path.data "C:\ProgramData\winlogbeat" keystore create
}

# Set the Redis password if it doesn't exist
if ((.\winlogbeat.exe --path.data "C:\ProgramData\winlogbeat" keystore list | Select-String REDIS_PASSWORD).Matches.Length -eq 0) {
    if($RedisPassword) {
        Write-Output "$RedisPassword" | .\winlogbeat.exe --path.data "C:\ProgramData\winlogbeat" keystore add REDIS_PASSWORD --stdin
    } else {
        .\winlogbeat.exe --path.data "C:\ProgramData\winlogbeat" keystore add REDIS_PASSWORD
    }
}

# Set ACL's of the $Env:ProgramData\winlogbeat folder to be the same as $Env:ProgramFiles\winlogbeat* (the main install path)
# This helps ensure that "normal" users aren't able to access the $Env:ProgramData\winlogbeat folder
Get-ACL -Path "$Env:ProgramFiles\winlogbeat*" | Set-ACL -Path "$Env:ProgramData\winlogbeat"
 
# Backup winlogbeat config if it exists
if (Test-Path -PathType Leaf .\winlogbeat.yml) {
    Copy-Item .\winlogbeat.yml .\winlogbeat.yml.bak
}

$winlogbeatSysmonCfg = @"
winlogbeat.event_logs:
    - name: Microsoft-Windows-Sysmon/Operational
    event_id: 3
    processors:
        - script:
            lang: javascript
            id: sysmon
            file: ${path.home}/module/sysmon/config/winlogbeat-sysmon.js
"@

# Add the windows event logs config to winlogbeat if it doesn't exist.
if ((Test-Path -PathType Leaf .\winlogbeat.yml) -and 
    ((Get-Content -Raw .\winlogbeat.yml | Select-String "winlogbeat\.event_logs:").Matches.Length -gt 0)) {
    Write-Output "Found Event Logs stanza in the existing winlogbeat configuration"
    Write-Output "Refusing to update winlogbeat Event Logs configuration"
    Write-Output "Please ensure the following configuration is present in`n`t$( (Resolve-Path .).Path )\winlogbeat.yml:"
    Write-Output ""
    Write-Output "$winlogbeatSysmonCfg"
    Write-Output ""
} else {
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
} else {
    Write-Output "" >> .\winlogbeat.yml
    Write-Output "$winlogbeatRedisCfg" >> .\winlogbeat.yml
}

PowerShell.exe -ExecutionPolicy UnRestricted -File .\install-service-winlogbeat.ps1
Start-Service winlogbeat
