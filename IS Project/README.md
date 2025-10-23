# Enhanced Host-Based Firewall

A comprehensive host-based firewall implementation with advanced features including packet capture, rule engine, stateful inspection, logging, monitoring, and configuration management.

## Features

### 🔍 Packet Capture Module
- Enhanced packet parsing with detailed metadata extraction
- Support for TCP, UDP, ICMP protocols
- TCP flags analysis
- Payload preview
- Real-time packet statistics

### 🛡️ Rule Engine Module
- Advanced filtering rules with multiple criteria
- Support for IP addresses, ports, protocols
- CIDR notation support
- Rule priority system
- Default action configuration

### 🔄 Stateful Inspection Module
- Connection state tracking
- TCP state machine implementation
- UDP connection monitoring
- Connection timeout management
- Bidirectional connection tracking

### 📋 Rule Management Module
- GUI-based rule management
- Add, edit, delete firewall rules
- Rule import/export functionality
- Rule validation
- Priority-based rule ordering

### 📊 Logging & Monitoring Module
- Comprehensive event logging
- Multiple log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Log rotation and retention
- Real-time monitoring metrics
- Performance statistics
- Security alerts

### ⚙️ Configuration & Policy Module
- Configuration management
- Security policy enforcement
- Network settings
- Performance tuning
- Policy evaluation engine

## Installation

1. Install Python 3.8 or higher
2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Run the firewall (choose one method):

**Method 1: Direct execution**
```bash
python firewall.py
```

**Method 2: Using startup script (recommended)**
```bash
python start_firewall.py
```

**Method 3: Using batch file (Windows)**
```bash
start_firewall.bat
```

**Method 4: Test modules first**
```bash
python test_modules.py
```

## Usage

### Starting the Firewall
1. Launch the application
2. Click "Start Firewall" on the Dashboard tab
3. Monitor activity in the Activity Log

### Managing Rules
1. Go to the "Rules" tab
2. Use the rule management interface to:
   - Add new rules
   - Edit existing rules
   - Delete rules
   - Import/export rule sets

### Monitoring
1. Go to the "Monitoring" tab
2. View real-time metrics
3. Monitor active connections
4. Check system performance

### Viewing Logs
1. Go to the "Logs" tab
2. View recent firewall events
3. Export logs for analysis

### Configuration
1. Go to the "Configuration" tab
2. Adjust firewall settings
3. Configure security policies
4. Set network parameters

## Architecture

The firewall is built with a modular architecture:

```
firewall.py (Main Application)
├── packet_capture.py (Packet Capture Module)
├── rule_engine.py (Rule Engine Module)
├── stateful_inspection.py (Stateful Inspection Module)
├── rule_management.py (Rule Management Module)
├── logging_monitoring.py (Logging & Monitoring Module)
└── configuration_policy.py (Configuration & Policy Module)
```

## Key Components

### EnhancedFirewall Class
- Main firewall controller
- Integrates all modules
- Provides unified interface

### EnhancedFirewallGUI Class
- Modern tabbed interface
- Real-time monitoring
- Rule management
- Configuration interface

## Security Features

- **Stateful Inspection**: Tracks connection states
- **Rule-based Filtering**: Flexible rule system
- **Intrusion Detection**: Monitors for suspicious activity
- **DoS Protection**: Rate limiting and connection limits
- **Logging**: Comprehensive audit trail

## Performance Features

- **Efficient Packet Processing**: Optimized packet handling
- **Connection Tracking**: Memory-efficient connection management
- **Log Rotation**: Prevents disk space issues
- **Background Processing**: Non-blocking operations

## Configuration Files

- `firewall_config.json`: Main configuration
- `policies.json`: Security policies
- `logs/`: Log files directory

## Requirements

- Windows 10/11
- Python 3.8+
- Administrator privileges (for packet capture)
- WinDivert driver (installed with pydivert)

## Troubleshooting

### Common Issues

1. **Permission Denied**: Run as Administrator
2. **WinDivert Error**: Ensure WinDivert driver is installed
3. **Import Errors**: Check all modules are in the same directory
4. **GUI Initialization Error**: Use `python start_firewall.py` instead of direct execution
5. **PyYAML Installation Error**: Try `pip install "pyyaml>=6.0.1,<7.0"`

### Quick Fixes

**If you get AttributeError during startup:**
```bash
python start_firewall.py
```

**If modules fail to import:**
```bash
python test_modules.py
```

**If PyYAML installation fails:**
```bash
pip install "pyyaml>=6.0.1,<7.0"
```

### Log Files

Check the following log files for troubleshooting:
- `logs/firewall.log`: General firewall events
- `logs/security.log`: Security-related events
- `logs/error.log`: Error messages
- `logs/performance.log`: Performance metrics

## Development

### Adding New Features

1. Create new module in separate file
2. Import in main firewall.py
3. Integrate with EnhancedFirewall class
4. Add GUI components as needed

### Testing

1. Test with different network scenarios
2. Verify rule effectiveness
3. Check logging functionality
4. Monitor performance metrics

## License

This project is for educational purposes. Use responsibly and in accordance with local laws and regulations.

## Contributing

1. Fork the repository
2. Create feature branch
3. Make changes
4. Test thoroughly
5. Submit pull request

## Support

For issues and questions:
1. Check the logs
2. Verify configuration
3. Test with minimal rules
4. Report issues with detailed information
