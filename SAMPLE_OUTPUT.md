# Sample Output Documentation

This document shows examples of the script's output and reports.

## Console Output Example

```
================================================================================
Cisco 9800 Series WLC Certificate Status Reporter
================================================================================

Security Features:
   - AES-128-CBC encryption for passwords
   - PBKDF2-SHA256 key derivation (100k iterations)
   - Session-based credential management
   - Automatic memory cleanup

============================================================
WLC Authentication Required
============================================================
Session will timeout after 30 minutes of inactivity

Enter WLC username: admin

Authentication successful (Session ID: a7f3e912)
Credentials encrypted in memory with AES-128

Environment validated
Email: your-email@example.com
Recipients: team@company.com

2025-01-15 08:00:15 - INFO - Loaded 5 WLC devices from wlc.json
2025-01-15 08:00:15 - INFO - Processing 5 WLCs using 10 concurrent threads
2025-01-15 08:00:18 - INFO - [Thread-1] Checking connectivity to WLC-SITE01 (192.168.1.10)...
2025-01-15 08:00:18 - INFO - [Thread-2] Checking connectivity to WLC-SITE02 (192.168.1.11)...
2025-01-15 08:00:18 - INFO - [Thread-3] Checking connectivity to WLC-SITE03 (192.168.1.12)...
2025-01-15 08:00:18 - INFO - [Thread-4] Checking connectivity to WLC-SITE04 (192.168.1.13)...
2025-01-15 08:00:18 - INFO - [Thread-5] Checking connectivity to WLC-SITE05 (192.168.1.14)...
2025-01-15 08:00:19 - INFO - [Thread-1] Connecting to WLC-SITE01 (192.168.1.10)...
2025-01-15 08:00:22 - INFO - [Thread-1] Connection successful to WLC-SITE01
2025-01-15 08:00:22 - INFO - [Thread-1] Running command: 'show crypto pki certificates'...
2025-01-15 08:00:45 - INFO - [Thread-1] Command completed successfully
2025-01-15 08:00:45 - INFO - [Thread-1] Connection closed
2025-01-15 08:00:46 - INFO - Progress: 1/5 (20.0%)
2025-01-15 08:00:46 - INFO - [OK] WLC-SITE01
...
2025-01-15 08:02:15 - INFO - Progress: 5/5 (100.0%)
2025-01-15 08:02:15 - INFO - [OK] WLC-SITE05
2025-01-15 08:02:15 - INFO - Processing certificate data...
2025-01-15 08:02:16 - INFO - Creating Excel report: WLC_Certificate_Status_Report_15 Jan 2025 0802.xlsx
2025-01-15 08:02:18 - INFO - Excel report created: WLC_Certificate_Status_Report_15 Jan 2025 0802.xlsx

============================================================
EXECUTION SUMMARY
============================================================
2025-01-15 08:02:18 - INFO - Certificate report saved: WLC_Certificate_Status_Report_15 Jan 2025 0802.xlsx
2025-01-15 08:02:18 - INFO - Total WLCs: 5
2025-01-15 08:02:18 - INFO - Successful: 5/5 (100.0%)
2025-01-15 08:02:18 - INFO - Failed: 0/5
2025-01-15 08:02:18 - INFO - Total certificates: 87
2025-01-15 08:02:18 - INFO - Expired certificates: 2
2025-01-15 08:02:18 - INFO - Expiring soon (< 1 year): 5
2025-01-15 08:02:18 - INFO - Execution time: 123.45s (2.1m)
============================================================

2025-01-15 08:02:18 - INFO - Sending email report...
2025-01-15 08:02:21 - INFO - Email sent successfully to team@company.com
2025-01-15 08:02:21 - INFO - Cleaning up secure session...

WLC Certificate Status check completed successfully
```

## Excel Report Structure

### Report Headers

| Column | Description | Example |
|--------|-------------|---------|
| REPORT DATE | Date of report generation | 15-01-2025 |
| REPORT TIME | Time of report generation | 08:02 UTC |
| REGION | Geographic region | Americas |
| SITE ID | Site identifier | SITE01 |
| WLC HOSTNAME | WLC hostname | WLC-SITE01 |
| WLC IP ADDRESS | WLC management IP | 192.168.1.10 |
| CERT TYPE | Certificate type | Certificate, CA Certificate, Router Self-Signed |
| CERT NAME | Certificate name | guestportal.company.com |
| START DATE | Certificate valid from | 06:45:50 GMT May 13 2025 |
| END DATE | Certificate valid until | 04:00:00 GMT Jun 9 2026 |
| ASSOCIATED TRUSTPOINTS | Trustpoint names | guestportal.company.com-2025-for-wlc.pfx |
| STATUS | Certificate status | Available |
| STORAGE | Storage location | nvram:EntrustOVTLS#CFF5.cer |
| REMARKS | Expiry status | OK / 6 months remaining, renewal due: 09-06-2026 / EXPIRED |

### Sample Report Data

```
REPORT DATE: 15-01-2025
REPORT TIME: 08:02 UTC
REGION: Americas
SITE ID: SITE01
WLC HOSTNAME: WLC-SITE01
WLC IP ADDRESS: 192.168.1.10
CERT TYPE: Certificate
CERT NAME: guestportal.company.com
START DATE: 06:45:50 GMT May 13 2025
END DATE: 04:00:00 GMT Jun 9 2026
ASSOCIATED TRUSTPOINTS: guestportal.company.com-2025-for-wlc.pfx
STATUS: Available
STORAGE: nvram:EntrustOVTLS#CFF5.cer
REMARKS: 5 months remaining, renewal due: 09-06-2026
```

### Color Coding

- **Red Background (White Text)**: EXPIRED certificates
- **Yellow Background (Bold Text)**: Certificates expiring within 1 year
- **White Background**: OK certificates (valid for > 1 year)

## Email Report Example

```
Subject: WLC Certificate Status Report - 15 JAN 2025

Hello,

Attached is the Cisco WLC Certificate Status Report generated on 15 January 2025 at 08:02 UTC.

EXECUTION SUMMARY:
==================
Total WLCs Processed: 5
Successful Connections: 5
Failed Connections: 0
Total Certificates Found: 87
Expired Certificates: 2
Certificates Expiring Soon: 5
Execution Time: 123.45 seconds (2.1 minutes)

This report contains certificate status information from all WLCs in the environment.

For detailed error logs, check the wlc_cert_errors.log file.

Regards,
WLC Certificate Monitoring System

Attachments:
- WLC_Certificate_Status_Report_15 Jan 2025 0802.xlsx
```

## Error Report Example (with failures)

```
Subject: WLC Certificate Status Report - 15 JAN 2025

Hello,

Attached is the Cisco WLC Certificate Status Report generated on 15 January 2025 at 08:02 UTC.

EXECUTION SUMMARY:
==================
Total WLCs Processed: 5
Successful Connections: 3
Failed Connections: 2
Total Certificates Found: 52
Expired Certificates: 1
Certificates Expiring Soon: 3
Execution Time: 98.32 seconds (1.6 minutes)

FAILURE DETAILS:
- WLC-SITE04 (192.168.1.13): WLC not reachable (ping failed)
- WLC-SITE05 (192.168.1.14): Error connecting to WLC-SITE05: Authentication failed

This report contains certificate status information from all WLCs in the environment.

For detailed error logs, check the wlc_cert_errors.log file.

Regards,
WLC Certificate Monitoring System

Attachments:
- WLC_Certificate_Status_Report_15 Jan 2025 0802.xlsx
- wlc_cert_errors.log
```

## Certificate Types Captured

### 1. End-Entity Certificates
```
CERT TYPE: Certificate
CERT NAME: guestportal.company.com
START DATE: 06:45:50 GMT May 13 2025
END DATE: 04:00:00 GMT Jun 9 2026
TRUSTPOINTS: guestportal.company.com-2025-for-wlc.pfx
STATUS: Available
STORAGE: nvram:EntrustOVTLS#CFF5.cer
REMARKS: 5 months remaining, renewal due: 09-06-2026
```

### 2. CA Certificates
```
CERT TYPE: CA Certificate
CERT NAME: Cisco Manufacturing CA SHA2
START DATE: 13:50:58 GMT Nov 12 2012
END DATE: 13:00:17 GMT Nov 12 2037
TRUSTPOINTS: CISCO_IDEVID_CMCA2_SUDI Trustpool
STATUS: Available
STORAGE: nvram:CiscoManuf#7785CA.cer
REMARKS: OK
```

### 3. Router Self-Signed Certificates
```
CERT TYPE: Router Self-Signed Certificate
CERT NAME: IOS-Self-Signed-Certificate-2552746395
START DATE: 20:51:34 GMT Feb 13 2020
END DATE: 00:00:00 GMT Jan 1 2030
TRUSTPOINTS: TP-self-signed-2552746395
STATUS: Available
STORAGE: nvram:IOS-Self-Sig#1.cer
REMARKS: OK
```

## Remarks Examples

### OK (Valid > 1 year)
```
REMARKS: OK
```

### Expiring Soon (< 1 year, > 1 month)
```
REMARKS: 11 months remaining, renewal due: 15-12-2025
REMARKS: 6 months remaining, renewal due: 15-07-2025
REMARKS: 3 months remaining, renewal due: 15-04-2025
```

### Expiring Very Soon (< 1 month)
```
REMARKS: 25 days remaining, renewal due: 09-02-2025
REMARKS: 10 days remaining, renewal due: 25-01-2025
REMARKS: 3 days remaining, renewal due: 18-01-2025
```

### Expired
```
REMARKS: EXPIRED
```

## Log File Examples

### Main Log (wlc_cert_checker.log)
```
2025-01-15 08:00:15,123 - INFO - Loaded 5 WLC devices from wlc.json
2025-01-15 08:00:15,124 - INFO - Processing 5 WLCs using 10 concurrent threads
2025-01-15 08:00:18,456 - INFO - [Thread-1] Checking connectivity to WLC-SITE01 (192.168.1.10)...
2025-01-15 08:00:19,123 - INFO - [Thread-1] Connecting to WLC-SITE01 (192.168.1.10)...
2025-01-15 08:00:22,789 - INFO - [Thread-1] Connection successful to WLC-SITE01
2025-01-15 08:00:22,790 - INFO - [Thread-1] Running command: 'show crypto pki certificates'...
2025-01-15 08:00:45,234 - INFO - [Thread-1] Command completed successfully
2025-01-15 08:00:45,235 - INFO - [Thread-1] Connection closed
2025-01-15 08:00:46,100 - INFO - Progress: 1/5 (20.0%)
2025-01-15 08:00:46,101 - INFO - [OK] WLC-SITE01
2025-01-15 08:02:15,678 - INFO - Processing certificate data...
2025-01-15 08:02:16,234 - INFO - Creating Excel report: WLC_Certificate_Status_Report_15 Jan 2025 0802.xlsx
2025-01-15 08:02:18,567 - INFO - Excel report created: WLC_Certificate_Status_Report_15 Jan 2025 0802.xlsx
2025-01-15 08:02:18,568 - INFO - Total WLCs: 5
2025-01-15 08:02:18,569 - INFO - Successful: 5/5 (100.0%)
2025-01-15 08:02:18,570 - INFO - Email sent successfully to team@company.com
```

### Error Log (wlc_cert_errors.log)
```
2025-01-15 08:00:25,123 - ERROR - WLC-SITE04 - Ping failed to 192.168.1.13
2025-01-15 08:00:32,456 - ERROR - WLC-SITE05 - Connection error: Authentication failed
2025-01-15 08:00:32,457 - ERROR - WLC-SITE05 - Could not establish SSH connection
```

## Sample Excel Report Visual Layout

```
┌─────────────┬──────────────┬─────────┬──────────┬──────────────┬────────────────┬───────────────┬──────────────────────────┬─────────────────────────┬─────────────────────────┬─────────────────────────┬───────────┬─────────────────────────┬──────────────────────────────────────┐
│ REPORT DATE │ REPORT TIME  │ REGION  │ SITE ID  │ WLC HOSTNAME │ WLC IP ADDRESS │ CERT TYPE     │ CERT NAME                │ START DATE              │ END DATE                │ ASSOCIATED TRUSTPOINTS  │ STATUS    │ STORAGE                 │ REMARKS                              │
├─────────────┼──────────────┼─────────┼──────────┼──────────────┼────────────────┼───────────────┼──────────────────────────┼─────────────────────────┼─────────────────────────┼─────────────────────────┼───────────┼─────────────────────────┼──────────────────────────────────────┤
│ 15-01-2025  │ 08:02 UTC    │ Americas│ SITE01   │ WLC-SITE01   │ 192.168.1.10   │ Certificate   │ guestportal.company.com  │ 06:45:50 GMT May 13 2025│ 04:00:00 GMT Jun 9 2026 │ guestportal.pfx         │ Available │ nvram:Entrust#CFF5.cer  │ 5 months remaining, renewal due...   │
│ 15-01-2025  │ 08:02 UTC    │ Americas│ SITE01   │ WLC-SITE01   │ 192.168.1.10   │ CA Cert       │ Cisco Manufacturing CA   │ 13:50:58 GMT Nov 12 2012│ 13:00:17 GMT Nov 12 2037│ CISCO_IDEVID_CMCA2_SUDI │ Available │ nvram:CiscoManuf#1.cer  │ OK                                   │
│ 15-01-2025  │ 08:02 UTC    │ EMEA    │ SITE02   │ WLC-SITE02   │ 192.168.1.11   │ Certificate   │ webauth.company.com      │ 10:00:00 GMT Jan 1 2024 │ 10:00:00 GMT Jan 1 2025 │ webauth-cert.pfx        │ Available │ nvram:WebAuth#AB12.cer  │ EXPIRED                              │
└─────────────┴──────────────┴─────────┴──────────┴──────────────┴────────────────┴───────────────┴──────────────────────────┴─────────────────────────┴─────────────────────────┴─────────────────────────┴───────────┴─────────────────────────┴──────────────────────────────────────┘

Header Row: Blue background (#366092), White text, Bold
Data Rows: White background, Black text
EXPIRED Remarks: Red background (#FF6B6B), White text, Bold
Expiring Soon Remarks: Yellow background (#FFD93D), Black text, Bold
```

## Statistics Summary

### Typical Certificate Counts per WLC
- **Cisco SUDI Certificates**: 3-5 (manufacturer installed)
- **CA Certificates**: 5-10 (chain of trust)
- **Guest Portal Certificates**: 1-2 (SSL/TLS for guest access)
- **RADSEC Certificates**: 1-2 (secure RADIUS)
- **Internal Certificates**: 1-3 (company PKI)
- **Self-Signed Certificates**: 1 (router generated)

### Total per Environment
- **Small (1-10 WLCs)**: 100-200 certificates
- **Medium (11-50 WLCs)**: 500-1000 certificates
- **Large (51-100 WLCs)**: 1500-2000 certificates
- **Enterprise (100+ WLCs)**: 2000+ certificates

## Report File Naming Convention

```
WLC_Certificate_Status_Report_<DD> <MMM> <YYYY> <HHMM>.xlsx

Examples:
- WLC_Certificate_Status_Report_15 Jan 2025 0802.xlsx
- WLC_Certificate_Status_Report_23 Feb 2025 1430.xlsx
- WLC_Certificate_Status_Report_01 Mar 2025 0600.xlsx
```

## Command Line Output Examples

### Successful Run
```bash
$ python run_job.py
================================================================================
Cisco 9800 Series WLC Certificate Status Reporter
================================================================================
...
WLC Certificate Status check completed successfully
$ echo $?
0
```

### Failed Run
```bash
$ python run_job.py
================================================================================
Cisco 9800 Series WLC Certificate Status Reporter
================================================================================
...
Error: wlc.json not found
Use --create-json to create sample file

WLC Certificate Status check failed
$ echo $?
1
```

### Help Output
```bash
$ python run_job.py --help
usage: run_job.py [-h] [--create-json] [--create-env] [--test-env] [--no-email]
                  [--email EMAIL [EMAIL ...]] [--threads THREADS]

Cisco 9800 WLC Certificate Status Reporter

optional arguments:
  -h, --help            show this help message and exit
  --create-json         Create sample JSON file
  --create-env          Create sample .env file
  --test-env            Test environment configuration
  --no-email            Do not send email report
  --email EMAIL [EMAIL ...]
                        Email recipients (space-separated)
  --threads THREADS     Concurrent threads (default: 10)

Examples:
  python run_job.py                          # Run with defaults
  python run_job.py --create-json            # Create sample JSON
  python run_job.py --create-env             # Create sample .env
  python run_job.py --test-env               # Test configuration
  python run_job.py --no-email               # Run without email
  python run_job.py --threads 5              # Use 5 threads
  python run_job.py --email user@example.com # Custom recipients
```

## Performance Metrics

### Typical Execution Times

| WLC Count | Threads | Avg Time per WLC | Total Time |
|-----------|---------|------------------|------------|
| 5 | 5 | 2 min | 2-3 min |
| 10 | 10 | 2 min | 2-4 min |
| 25 | 10 | 2 min | 5-8 min |
| 50 | 15 | 2 min | 7-12 min |
| 100 | 20 | 2 min | 10-20 min |

### Network Impact
- **Bandwidth**: ~1-2 MB per WLC (certificate output)
- **Connections**: SSH (port 22) only
- **Protocol**: SSHv2
- **Impact**: Minimal (read-only commands)

---

**Note**: All sample data shown is for illustration purposes. Actual certificate names, dates, and details will vary based on your environment.