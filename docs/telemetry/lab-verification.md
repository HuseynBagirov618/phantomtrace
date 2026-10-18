# Lab Verification

## Lab machines

| Role | OS | Hostname | IP address | Notes |
|---|---|---|---|---|
| Windows victim/evaluation VM | TBD | TBD | TBD | Event source |
| Kali attacker VM | Kali Linux | TBD | TBD | Test source |

## Network

- Network type: Host-only
- Internet access: TBD
- Windows IP: 192.168.14.130
- Kali IP: 192.168.14.128
- Ping Windows from Kali: yes
- Ping Kali from Windows: yes

## Sysmon configuration

- Sysmon installed: yes
- Sysmon config file: sysmonconfig.xml
- Sysmon config SHA-256: 055FEBC600E6D7448CDF3812307275912927A62B1F94D0D933B64B294BC87162

## Event verification table

| Capability | Event ID | Source/channel | Observed? | Important fields seen | Notes |
|---|---:|---|---|---|---|
| Successful logon | 4624 | Security | yes | TBD | TBD |
| Failed logon | 4625 | Security | yes | TBD | TBD |
| Process creation | 4688 | Security | yes | TBD | TBD |
| Process creation | 1 | Sysmon/Operational | yes | TBD | TBD |
| Network connection | 3 | Sysmon/Operational | yes | TBD | TBD |
| File creation | 11 | Sysmon/Operational | yes | TBD | TBD |
| Scheduled task creation | 4698 | Security | yes | TBD | TBD |
| PowerShell script block | 4104 | PowerShell/Operational | yes | TBD | TBD |

## Day 2 result

- Ready for Day 3 dataset capture: yes

## Problems or surprises

- TBD