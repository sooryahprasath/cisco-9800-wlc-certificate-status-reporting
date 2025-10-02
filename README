# Cisco 9800 Series WLC Certificate Status Reporter

A secure, multi-threaded Python application for collecting and reporting certificate status information from Cisco 9800 Series Wireless LAN Controllers (both on-premises and cloud-based).

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)

## Features

### Cisco 9800 Series Support
Compatible with all Cisco 9800 Series WLC models:
- **C9800-CL (Cloud)**
- **C9800-40**
- **C9800-80**
- **C9800-L-C**
- **C9800-L-F**

### Key Capabilities
- **Flexible Execution**: Process all WLCs or select specific sites
- **Secure Credential Management**: AES-128-CBC encryption for passwords in memory with PBKDF2-SHA256 key derivation
- **Multi-threaded Processing**: Concurrent connections to multiple WLCs for faster execution
- **Comprehensive Reporting**: Excel reports with detailed certificate information including expiry tracking
- **Email Integration**: Optional automatic email delivery of reports with attachments
- **Session Management**: 30-minute session timeout with automatic credential cleanup
- **Error Handling**: Robust error logging and retry mechanisms
- **Memory Protection**: Core dumps disabled, automatic memory cleanup

## Security Features

- AES-128-CBC encryption for passwords in memory
- PBKDF2-SHA256 key derivation (100,000 iterations - OWASP recommended)
- Session-based credential management with automatic timeout
- Automatic memory cleanup and secure password disposal
- Core dumps disabled to prevent credential leakage
- Environment-based configuration (credentials never hardcoded)

## Requirements

### Python Version
- Python 3.8 or higher

### Dependencies
```
netmiko>=4.0.0
python-dotenv>=0.19.0
cryptography>=3.4.8
openpyxl>=3.0.9
pytz>=2021.3
python-dateutil>=2.8.2
ping3>=4.0.0
```

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/cisco-9800-wlc-certificate-status-reporting.git
cd cisco-9800-wlc-certificate-status-reporting
```

### 2. Create virtual environment (recommended)
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Create configuration files
```bash
python run_job.py --create-env
python run_job.py --create-json
```

### 5. Configure environment
```bash
# Copy sample environment file
cp .env.example .env

# Edit .env with your credentials
nano .env  # or use your preferred editor

# Set secure permissions
chmod 600 .env
```

### 6. Update WLC data
Edit `wlc.json` with your actual WLC information.

## Configuration

### Environment Variables (.env file)

Create a `.env` file in the project root:

```bash
# Email Configuration (REQUIRED for email reports)
SENDER_EMAIL=your-email@example.com
SENDER_PASSWORD=your-app-password
DEFAULT_RECIPIENTS=recipient1@example.com,recipient2@example.com

# SMTP Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587

# File Configuration
WLC_DATA_FILE=wlc.json
LOG_DIR=logs

# Processing Configuration
MAX_THREADS=10
COMMAND_TIMEOUT=180
CONNECTION_TIMEOUT=180
PING_TIMEOUT=5
MAX_RETRIES=3

# Report Configuration
REPORT_TIMEZONE=UTC
```

### WLC Data File (wlc.json)

Create a JSON file with your WLC information:

```json
[
    {
        "SITE ID": "SITE01",
        "HOSTNAME": "WLC-01",
        "IP ADDRESS": "192.168.1.10",
        "MODEL": "C9800-80-K9",
        "REGION": "Americas",
        "CITY": "New York",
        "TIMEZONE": "UTC-5"
    },
    {
        "SITE ID": "SITE02",
        "HOSTNAME": "WLC-02",
        "IP ADDRESS": "192.168.1.11",
        "MODEL": "C9800-CL-K9",
        "REGION": "EMEA",
        "CITY": "London",
        "TIMEZONE": "UTC+0"
    }
]
```

**Note**: The script processes ALL WLCs listed in this file. To run for specific sites:
- Create a separate JSON file (e.g., `wlc_site1.json`) with only desired WLCs
- Run with: `WLC_DATA_FILE=wlc_site1.json python run_job.py`

## Gmail App Password Setup

### Step-by-step guide:

1. **Enable 2-Factor Authentication**
   - Go to https://myaccount.google.com/security
   - Under "Signing in to Google", click "2-Step Verification"
   - Follow prompts to enable 2FA

2. **Generate App Password**
   - Go to https://myaccount.google.com/apppasswords
   - Sign in again if prompted
   - Under "Select app", choose "Mail"
   - Under "Select device", choose "Other (Custom name)"
   - Enter "WLC Certificate Reporter"
   - Click "Generate"

3. **Copy App Password**
   - Google displays a 16-character password (e.g., `abcd efgh ijkl mnop`)
   - Copy without spaces: `abcdefghijklmnop`
   - Paste into your `.env` file as `SENDER_PASSWORD`

### Security Tips
- Never share app passwords
- Revoke and regenerate if compromised
- Each application should have unique app password

Example `.env` configuration:
```bash
SENDER_EMAIL=your.email@gmail.com
SENDER_PASSWORD=abcdefghijklmnop
DEFAULT_RECIPIENTS=team@company.com
```

## Usage

### Basic Usage
```bash
# Run with default settings (prompts for WLC credentials)
# Processes ALL WLCs in wlc.json and sends email report
python run_job.py
```

### Running Without Email
If you don't want to configure email or don't need email reports:

```bash
# Run without sending email (report saved locally only)
python run_job.py --no-email
```

This is useful for:
- Testing the script
- Environments without email access
- Manual report distribution
- Automated systems with custom notifications

### Processing Specific Sites

The script processes ALL WLCs in `wlc.json` by default. To run for specific sites:

#### Option 1: Create separate JSON files
```bash
# Create site-specific JSON file
cat > wlc_site1.json << EOF
[
    {
        "SITE ID": "SITE01",
        "HOSTNAME": "WLC-01",
        "IP ADDRESS": "192.168.1.10",
        "MODEL": "C9800-80-K9",
        "REGION": "Americas",
        "CITY": "New York",
        "TIMEZONE": "UTC-5"
    }
]
EOF

# Run for specific site
WLC_DATA_FILE=wlc_site1.json python run_job.py
```

#### Option 2: Temporarily edit wlc.json
```bash
# Backup original file
cp wlc.json wlc_all.json

# Edit wlc.json to include only desired sites
nano wlc.json

# Run the script
python run_job.py

# Restore original file
mv wlc_all.json wlc.json
```

#### Option 3: Maintain multiple configuration files
```bash
# File structure
wlc_all.json          # All WLCs
wlc_region1.json      # Region 1 only
wlc_region2.json      # Region 2 only
wlc_production.json   # Production WLCs
wlc_test.json         # Test WLCs

# Run with specific file
WLC_DATA_FILE=wlc_region1.json python run_job.py
```

### Using Threads (Concurrent Processing)

The script uses multi-threading for parallel WLC processing:

```bash
# Use default 10 threads
python run_job.py

# Use 5 threads (conservative)
python run_job.py --threads 5

# Use 20 threads (aggressive)
python run_job.py --threads 20

# Use 1 thread (sequential)
python run_job.py --threads 1
```

#### Thread Count Guidelines

| Scenario | Recommended Threads | Reason |
|----------|-------------------|---------|
| Small environment (1-10 WLCs) | 3-5 | Avoid network overload |
| Medium environment (11-50 WLCs) | 10-15 | Balance speed/stability |
| Large environment (50+ WLCs) | 15-25 | Maximize throughput |
| Network issues/high latency | 3-5 | Reduce timeout errors |
| Testing/troubleshooting | 1-2 | Easier debugging |
| Fast network, powerful server | 20-30 | Maximum performance |
| Cloud WLCs with rate limiting | 5-10 | Respect API limits |

#### Performance Examples

Environment: 50 WLCs, avg 2 minutes per WLC
- **Sequential (1 thread)**: ~100 minutes total
- **10 threads**: ~10 minutes total
- **20 threads**: ~5 minutes total

### Command Line Options

```bash
# Create sample configuration files
python run_job.py --create-env
python run_job.py --create-json

# Test environment configuration
python run_job.py --test-env

# Run without email (report saved locally)
python run_job.py --no-email

# Custom email recipients (overrides .env)
python run_job.py --email user1@example.com user2@example.com

# Custom thread count
python run_job.py --threads 5

# Combine options
python run_job.py --no-email --threads 15

# Run for specific sites
WLC_DATA_FILE=wlc_site1.json python run_job.py --threads 5
```

## Complete Examples

### Example 1: First Time Setup
```bash
# Create configuration templates
python run_job.py --create-env
python run_job.py --create-json

# Copy and edit configuration
cp .env.example .env
nano .env  # Add your email credentials

# Edit WLC data
nano wlc.json  # Add your WLC information

# Test configuration
python run_job.py --test-env

# Test run without email
python run_job.py --no-email --threads 5

# Full run with email
python run_job.py
```

### Example 2: Quick Test Run
```bash
# Test with 2 WLCs without email
python run_job.py --no-email --threads 2
```

### Example 3: Production Run - All Sites
```bash
# Full run with all WLCs, 10 threads, with email
python run_job.py
```

### Example 4: Single Site Emergency Check
```bash
# Create temporary JSON
echo '[{"SITE ID":"SITE01","HOSTNAME":"WLC-01","IP ADDRESS":"10.1.1.10","MODEL":"C9800-80-K9","REGION":"US","CITY":"NYC","TIMEZONE":"UTC-5"}]' > wlc_emergency.json

# Run quickly with 1 thread, no email
WLC_DATA_FILE=wlc_emergency.json python run_job.py --no-email --threads 1
```

### Example 5: Regional Reports
```bash
# Run Americas region
WLC_DATA_FILE=wlc_americas.json python run_job.py --email americas-team@company.com

# Run EMEA region
WLC_DATA_FILE=wlc_emea.json python run_job.py --email emea-team@company.com
```

## Output

The script generates:

### 1. Excel Report
`WLC_Certificate_Status_Report_DD MMM YYYY HHMM.xlsx`

Contains:
- Report date and time
- WLC details (Region, Site ID, Hostname, IP)
- Certificate type (Certificate, CA Certificate, Router Self-Signed)
- Certificate name
- Validity dates (start/end)
- Associated trustpoints
- Certificate status
- Storage location
- **Remarks** (color-coded):
  - **Red**: EXPIRED
  - **Yellow**: Expiring soon (< 1 year) with renewal date
  - **Green**: OK (> 1 year valid)

### 2. System Logs
- `logs/wlc_cert_checker.log` - Main execution log
- `logs/wlc_cert_errors.log` - Error-specific log
- `logs/wlc_cert_session_*.log` - Individual session logs

## Email Configuration

### Gmail (Recommended)
See [Gmail App Password Setup](#gmail-app-password-setup) section above.

### Other Email Providers

#### Office 365
```bash
SMTP_SERVER=smtp-mail.outlook.com
SMTP_PORT=587
```

#### Yahoo
```bash
SMTP_SERVER=smtp.mail.yahoo.com
SMTP_PORT=587
```

### Running Without Email
You don't need email configuration to use the script:

```bash
python run_job.py --no-email
```

## Certificate Expiry Logic

The script automatically evaluates certificates and provides remarks:

| Condition | Remarks | Color |
|-----------|---------|-------|
| Certificate expired | "EXPIRED" | Red |
| Expiry < 30 days | "X days remaining, renewal due: DD-MM-YYYY" | Yellow |
| Expiry < 1 year | "X months remaining, renewal due: DD-MM-YYYY" | Yellow |
| Expiry > 1 year | "OK" | White |

## How It Works

1. **Authentication**: User provides WLC credentials (encrypted in memory)
2. **Connectivity Check**: Each WLC is pinged before connection
3. **Parallel Processing**: Multiple WLCs processed concurrently
4. **Command Execution**: `show crypto pki certificates` executed on each WLC
5. **Data Parsing**: Certificate information extracted and structured
6. **Expiry Calculation**: Certificate validity evaluated
7. **Report Generation**: Excel report created with formatting
8. **Email Delivery**: Report automatically emailed (optional)
9. **Cleanup**: Secure cleanup of credentials from memory

## Troubleshooting

### Authentication Failures
- Verify WLC credentials
- Check network connectivity
- Ensure WLC allows SSH connections
- Verify user has appropriate permissions

### Connection Timeouts
- Increase `CONNECTION_TIMEOUT` in `.env`
- Check firewall rules
- Verify WLC is reachable (ping test)
- Reduce thread count

### Email Sending Failures
- Verify email credentials in `.env`
- Check SMTP server and port
- Use app passwords (not account passwords)
- Test with `--test-env`

### Missing Dependencies
```bash
pip install -r requirements.txt --upgrade
```

### Permission Errors
```bash
chmod 600 .env
chmod +x run_job.py
```

## Performance Tuning

### Thread Count by Environment

| WLC Count | Network Quality | Threads | Expected Runtime* |
|-----------|----------------|---------|-------------------|
| 1-5 | Any | 3-5 | 2-5 minutes |
| 6-20 | Good | 10 | 3-8 minutes |
| 21-50 | Good | 15 | 5-12 minutes |
| 51-100 | Excellent | 20-25 | 8-20 minutes |
| 100+ | Excellent | 25-30 | 15-30 minutes |

*Assuming avg 2 minutes per WLC

### Timeout Configuration
- `COMMAND_TIMEOUT`: Increase if WLCs have many certificates (default: 180s)
- `CONNECTION_TIMEOUT`: Adjust based on network latency (default: 180s)
- `PING_TIMEOUT`: Network ping timeout (default: 5s)

## Site-Specific Processing

### Use Cases

#### Single Site Troubleshooting
```bash
echo '[{"SITE ID":"SITE01","HOSTNAME":"WLC-01","IP ADDRESS":"10.1.1.10","MODEL":"C9800-80-K9","REGION":"US","CITY":"NYC","TIMEZONE":"UTC"}]' > wlc_single.json
WLC_DATA_FILE=wlc_single.json python run_job.py --no-email --threads 1
```

#### Regional Reports
```bash
# Weekly reports by region
WLC_DATA_FILE=wlc_americas.json python run_job.py --email americas@company.com
WLC_DATA_FILE=wlc_emea.json python run_job.py --email emea@company.com
WLC_DATA_FILE=wlc_apac.json python run_job.py --email apac@company.com
```

#### Production vs Test
```bash
# Daily production monitoring
WLC_DATA_FILE=wlc_production.json python run_job.py

# Weekly test environment check
WLC_DATA_FILE=wlc_test.json python run_job.py --no-email
```

## Security Best Practices

1. Never commit `.env` file - Add to `.gitignore`
2. Set restrictive file permissions: `chmod 600 .env`
3. Use app passwords instead of account passwords
4. Rotate credentials regularly
5. Review logs for unauthorized access
6. Use network segmentation for WLC access
7. Implement RBAC on WLC devices
8. Monitor for unusual access patterns
9. Regular security audits
10. Document security procedures

## Logging

Logs are stored in the `logs/` directory:

- **wlc_cert_checker.log**: Main execution log (INFO level)
- **wlc_cert_errors.log**: Error-specific log
- **wlc_cert_session_*.log**: Individual WLC session logs

## Scheduled Execution

### Linux/macOS (Cron)

```bash
# Edit crontab
crontab -e

# Run daily at 6 AM
0 6 * * * cd /path/to/cisco-9800-wlc-certificate-status-reporting && /path/to/venv/bin/python run_job.py

# Run weekly on Monday at 7 AM
0 7 * * 1 cd /path/to/cisco-9800-wlc-certificate-status-reporting && /path/to/venv/bin/python run_job.py

# Run monthly on 1st at 8 AM
0 8 1 * * cd /path/to/cisco-9800-wlc-certificate-status-reporting && /path/to/venv/bin/python run_job.py
```

### Windows (Task Scheduler)

```powershell
# Create scheduled task
$action = New-ScheduledTaskAction -Execute "C:\path\to\python.exe" -Argument "C:\path\to\run_job.py"
$trigger = New-ScheduledTaskTrigger -Daily -At 6am
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "WLC Certificate Check" -Description "Daily WLC certificate status check"
```

## Docker Support

### Dockerfile Example

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create logs directory
RUN mkdir -p logs

CMD ["python", "run_job.py"]
```

### Build and Run

```bash
# Build image
docker build -t wlc-cert-checker .

# Run with environment file
docker run --rm \
  --env-file .env \
  -v $(pwd)/wlc.json:/app/wlc.json \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/reports:/app/reports \
  wlc-cert-checker

# Run without email
docker run --rm \
  --env-file .env \
  -v $(pwd)/wlc.json:/app/wlc.json \
  -v $(pwd)/logs:/app/logs \
  wlc-cert-checker \
  python run_job.py --no-email
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: WLC Certificate Check

on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM UTC
  workflow_dispatch:

jobs:
  certificate-check:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
    
    - name: Run certificate check
      env:
        SENDER_EMAIL: ${{ secrets.SENDER_EMAIL }}
        SENDER_PASSWORD: ${{ secrets.SENDER_PASSWORD }}
        DEFAULT_RECIPIENTS: ${{ secrets.DEFAULT_RECIPIENTS }}
      run: |
        python run_job.py
    
    - name: Upload logs
      if: always()
      uses: actions/upload-artifact@v2
      with:
        name: logs
        path: logs/
```

## Customization

### Modifying Report Branding

Edit the `create_excel_report()` function to customize:

```python
# Change header colors
header_fill = PatternFill(start_color="YOUR_COLOR", end_color="YOUR_COLOR", fill_type="solid")

# Add company logo (requires openpyxl image support)
from openpyxl.drawing.image import Image
img = Image('company_logo.png')
ws.add_image(img, 'A1')

# Customize email body
body = f"""Hello Team,

Your custom message here...

"""
```

### Custom Certificate Validation Rules

Add custom logic in `calculate_cert_remarks()`:

```python
def calculate_cert_remarks(end_date_str):
    # Existing logic...
    
    # Custom rule: Flag certificates expiring in 90 days
    if 0 < days_remaining < 90:
        return f"CRITICAL: {days_remaining} days remaining", end_date
    
    # Custom rule: Different thresholds by certificate type
    # Add your custom logic here
    
    return remarks, end_date
```

### Extending to Other Cisco Devices

Modify `connect_to_wlc()` function:

```python
# Change device type
connection_config = {
    'device_type': 'cisco_ios',  # For switches/routers
    # or 'cisco_nxos', 'cisco_asa', etc.
    ...
}

# Modify commands for different platforms
commands = [
    "show crypto pki certificates",  # IOS/IOS-XE
    # or "show certificate" for other platforms
]
```

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Make your changes
4. Add tests if applicable
5. Update documentation
6. Test thoroughly
7. Commit changes (`git commit -am 'Add new feature'`)
8. Push to branch (`git push origin feature/improvement`)
9. Create Pull Request

### Code Style
- Follow PEP 8 guidelines
- Use meaningful variable names
- Add docstrings to functions
- Comment complex logic

### Testing
```bash
# Test configuration
python run_job.py --test-env

# Test with sample data
python run_job.py --no-email --threads 1
```

## FAQ

### Q: Can I run this for just one or two sites?
**A:** Yes! Create a separate JSON file with only those sites, or use:
```bash
WLC_DATA_FILE=wlc_specific.json python run_job.py
```

### Q: Do I need email configured to use this script?
**A:** No. Run with `--no-email` flag to skip email configuration entirely.

### Q: How do I handle certificate renewal alerts?
**A:** Certificates expiring within 1 year are automatically flagged in yellow with renewal dates in the report.

### Q: Can I run this on a schedule?
**A:** Yes. See [Scheduled Execution](#scheduled-execution) section for cron and Task Scheduler examples.

### Q: What if a WLC connection fails?
**A:** The script continues processing other WLCs. Failed connections are logged and included in the summary report.

### Q: How do I process only production WLCs?
**A:** Maintain separate JSON files and run:
```bash
WLC_DATA_FILE=wlc_production.json python run_job.py
```

### Q: Can I customize the report format?
**A:** Yes. See [Customization](#customization) section for modifying colors, layout, and content.

### Q: Is this script safe for production use?
**A:** Yes. It uses read-only commands and implements security best practices including encrypted credentials and session management.

### Q: How do I update the script?
**A:** Pull latest changes and update dependencies:
```bash
git pull origin main
pip install -r requirements.txt --upgrade
```

## Known Limitations

1. **SSH Access Required**: WLCs must allow SSH connections
2. **Network Connectivity**: Script requires network access to all WLCs
3. **Command Support**: Designed for Cisco 9800 WLC command output format
4. **Email Size**: Large environments may exceed email attachment limits
5. **Memory Usage**: Processing 100+ WLCs requires adequate system memory

## Roadmap

- [ ] Support for additional Cisco platforms (switches, routers)
- [ ] Web-based dashboard for viewing results
- [ ] Database integration for historical tracking
- [ ] REST API for programmatic access
- [ ] Slack/Teams webhook notifications
- [ ] Certificate auto-renewal integration
- [ ] Advanced filtering and search capabilities
- [ ] Multi-language report support

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built using [Netmiko](https://github.com/ktbyers/netmiko) for network device connections
- Uses [cryptography](https://cryptography.io/) for secure password handling
- Excel reports generated with [openpyxl](https://openpyxl.readthedocs.io/)
- Inspired by network automation best practices

## Support

For issues, questions, or contributions:

- Open an issue on GitHub
- Check existing issues for similar problems
- Provide detailed information including logs and error messages
- Include WLC model and software version

## Changelog

### Version 1.0.0 (Initial Release)
- Multi-threaded WLC processing
- Secure credential management with AES-128 encryption
- Excel report generation with certificate expiry tracking
- Email integration with attachments
- Comprehensive error handling and logging
- Session management with auto-timeout
- Support for all Cisco 9800 Series WLC models

## Author

Your Name - [@yourusername](https://github.com/yourusername)

## Disclaimer

This tool is provided as-is for network management purposes. Always ensure you have proper authorization before accessing network devices. The authors are not responsible for any misuse or damage caused by this tool. Use in accordance with your organization's security policies and applicable laws.

---

**Made with care for network engineers worldwide**