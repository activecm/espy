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
    [string]$RedisPassword=""
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

if (-not (Test-Path "$Env:programfiles\Sysmon" -PathType Container)) {
  Invoke-WebRequest -OutFile Sysmon.zip https://download.sysinternals.com/files/Sysmon.zip
  Expand-Archive .\Sysmon.zip
  rm .\Sysmon.zip
  mv .\Sysmon\ "$Env:programfiles"
}

echo @"
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
"@ > "$Env:programfiles\Sysmon\sysmon-net-only.xml"


& "$Env:programfiles\Sysmon\Sysmon64.exe" -accepteula -i "$Env:programfiles\Sysmon\sysmon-net-only.xml"

if (-not (Test-Path "$Env:programfiles\winlogbeat*" -PathType Container)) {
  Invoke-WebRequest -OutFile WinLogBeat.zip https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-7.5.2-windows-x86_64.zip
  Expand-Archive .\WinLogBeat.zip
  rm .\WinLogBeat.zip
  mv .\WinLogBeat\winlogbeat* "$Env:programfiles"
}

cd "$Env:programfiles\winlogbeat*\"
.\winlogbeat.exe --path.data "C:\ProgramData\winlogbeat" keystore create
if($RedisPassword) {
  Write-Output "$RedisPassword" | .\winlogbeat.exe --path.data "C:\ProgramData\winlogbeat" keystore add REDIS_PASSWORD --stdin
} else {
  .\winlogbeat.exe --path.data "C:\ProgramData\winlogbeat" keystore add REDIS_PASSWORD
}

# Set ACL's of the $Env:ProgramData\winlogbeat folder to be the same as $Env:ProgramFiles\winlogbeat* (the main install path)
# This helps ensure that "normal" users aren't able to access the $Env:ProgramData\winlogbeat folder
Get-ACL -Path "$Env:ProgramFiles\winlogbeat*" | Set-ACL -Path "$Env:ProgramData\winlogbeat"

rm .\winlogbeat.yml
echo @"
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
    event_id: 3
    processors:
      - script:
          lang: javascript
          id: sysmon
          file: ${path.home}/module/sysmon/config/winlogbeat-sysmon.js

output.redis:
  hosts:
    - ${RedisHost}:${RedisPort}
  ssl:
    enabled: true
    verification_mode: none
  key: "net-data:sysmon"
  password: `"`${REDIS_PASSWORD}`"
"@ > winlogbeat.yml
PowerShell.exe -ExecutionPolicy UnRestricted -File .\install-service-winlogbeat.ps1
Start-Service winlogbeat
