```markdown
# SETn3270 Project Updates and Technical Manual

**Code, concept and original tech docs by Soldier of Fortran (Phil Young)**
**Update by Kev Milne - pr0xym0r0n**

## Table of Contents

1. [Overview](#overview)
2. [Change Log](#change-log)
   - [SETn3270.py](#setn3270py)
   - [tn3270lib.py](#tn3270libpy)
3. [Technical Manual](#technical-manual)
   - [Introduction](#introduction)
   - [Installation](#installation)
   - [Usage](#usage)
     - [Launching the Tool](#launching-the-tool)
     - [Modifying TSO Screens](#modifying-tso-screens)
     - [File Operations](#file-operations)
     - [Sending Commands](#sending-commands)
   - [Features](#features)
   - [Benefits](#benefits)
   - [Risks](#risks)
   - [Use Cases](#use-cases)
     - [Penetration Testing](#penetration-testing)
     - [Honeypot Deployment](#honeypot-deployment)
4. [Security Considerations](#security-considerations)
5. [Contributing](#contributing)
6. [License](#license)
7. [Contact](#contact)
8. [Acknowledgments](#acknowledgments)

---

## Overview

**SETn3270** is a Python-based emulator designed to interact with TN3270 servers, commonly used for IBM mainframe communications. This tool facilitates the manipulation and monitoring of TSO (Time Sharing Option) screens by allowing users to modify screen content, handle file transfers, and automate command sequences.

Developed initially by **Phil Young (Soldier of Fortran)**, SETn3270 has been significantly enhanced and updated by **Kev Milne (pr0xym0r0n)**. These updates include the transition from Python 2 to Python 3, integration of CP037 (EBCDIC) encoding, and various stability, security, and efficiency improvements. Additionally, leveraging the capabilities of **ChatGPT**, further refinements and validations have been incorporated to ensure optimal performance and reliability.

This document outlines the recent changes made to the project, provides a comprehensive technical manual, and discusses its utility in security-related applications such as penetration testing and honeypot deployments.

---

## Change Log

### SETn3270.py

1. **Python 2 to Python 3 Conversion:**
   - **Syntax Updates:** Updated print statements to Python 3 syntax (`print()` function).
   - **Unicode Handling:** Enhanced Unicode support to handle CP037 encoding seamlessly.
   - **Library Updates:** Replaced deprecated Python 2 libraries with their Python 3 equivalents.
   - **Exception Handling:** Updated exception syntax to Python 3 standards.
   - **Division Behavior:** Ensured integer division behaves consistently with Python 3's default.

2. **Integration of CP037 Encoding:**
   - **Encoding and Decoding:** Implemented CP037 (EBCDIC) encoding for accurate representation and manipulation of mainframe screen data.
   - **Hex String Handling:** Enhanced functions to convert between hexadecimal strings and CP037-encoded bytes.

3. **Stabilization Enhancements:**
   - **Robust Error Handling:** Introduced comprehensive error checking and handling to prevent unexpected crashes.
   - **Input Validation:** Added validation for user inputs to ensure compatibility and prevent buffer overflows.
   - **Resource Management:** Improved management of network sockets and file handles to prevent resource leaks.

4. **Security Improvements:**
   - **SSL/TLS Support:** Enhanced secure connections with proper SSL/TLS certificate verification (configurable to enable/disable).
   - **Input Sanitization:** Ensured that all user inputs are sanitized to prevent injection attacks.
   - **Logging Enhancements:** Implemented secure logging practices to avoid leaking sensitive information.

5. **Efficiency Optimizations:**
   - **Buffer Management:** Optimized buffer handling to reduce memory usage and improve processing speed.
   - **Concurrency:** Introduced asynchronous operations where applicable to enhance responsiveness.
   - **Code Refactoring:** Streamlined code structure for better readability and maintainability.

6. **Feature Additions:**
   - **Custom Screen Modification:** Enabled dynamic modification of specific screen elements based on user input.
   - **Automated Command Execution:** Added capabilities to automate the sending of PF keys and commands.
   - **File Transfer Enhancements:** Improved support for both ASCII and binary file transfers with better error handling.

### tn3270lib.py

1. **Python 2 to Python 3 Conversion:**
   - **Syntax Updates:** Transitioned all Python 2 syntax to Python 3, including function definitions and module imports.
   - **Unicode Support:** Ensured all string operations correctly handle Unicode, especially for CP037 encoding.
   - **Library Compatibility:** Updated library imports and usage to align with Python 3 standards.

2. **CP037 Encoding Integration:**
   - **Encoding Functions:** Implemented functions to encode and decode data using CP037, ensuring accurate representation of mainframe characters.
   - **Hexadecimal Processing:** Enhanced hex processing functions to accommodate CP037-encoded data.

3. **Stabilization Enhancements:**
   - **Connection Management:** Improved handling of TN3270 connections, including reconnection logic and timeout management.
   - **Error Resilience:** Added mechanisms to gracefully handle unexpected data or connection drops without crashing.

4. **Security Improvements:**
   - **Secure Socket Handling:** Ensured all socket communications can optionally use SSL/TLS with proper certificate verification.
   - **Input Validation:** Validated all incoming and outgoing data to prevent malformed inputs from causing vulnerabilities.

5. **Efficiency Optimizations:**
   - **Data Processing:** Optimized data parsing and processing algorithms to handle large volumes of screen data efficiently.
   - **Asynchronous Operations:** Incorporated asynchronous I/O operations to enhance performance during high-latency network interactions.

6. **Feature Additions:**
   - **Structured Fields Support:** Added support for handling TN3270 structured fields, enabling more complex interactions with mainframe applications.
   - **Logging and Debugging:** Enhanced logging capabilities with configurable verbosity levels for easier debugging and monitoring.
   - **User Interaction Enhancements:** Improved methods for sending user inputs and interpreting mainframe responses.

---

## Technical Manual

### Introduction

**SETn3270** is a versatile tool designed to emulate TN3270 terminals, enabling interaction with IBM mainframe systems. By manipulating TSO screens, SETn3270 allows users to automate tasks, modify display content, and perform security assessments. This manual provides detailed instructions on installing, configuring, and utilizing SETn3270, along with insights into its benefits, risks, and applications in penetration testing and honeypot deployments.

Additionally, leveraging **ChatGPT**, users can effortlessly obtain CP037 hex-encoded characters for customizing front screens, as demonstrated in the "SIGHBERBANK" example. This collaboration ensures that modifications are accurate and efficiently implemented.

Developed initially by **Phil Young (Soldier of Fortran)**, SETn3270 has been significantly enhanced and updated by **Kev Milne (pr0xym0r0n)**. These updates include the transition from Python 2 to Python 3, integration of CP037 (EBCDIC) encoding, and various stability, security, and efficiency improvements, with further refinements and validations conducted with the assistance of **ChatGPT**.

### Installation

#### Prerequisites:

- **Python 3.6 or higher** installed on your system.
- **pip** package manager.
- **OpenSSL** (for SSL/TLS support, if required).

#### Clone the Repository:

```bash
git clone https://github.com/yourusername/SETn3270.git
cd SETn3270
```

#### Install Dependencies:

```bash
pip install -r requirements.txt
```

*Note: Ensure that all dependencies are compatible with Python 3.*

#### Make the Script Executable (Optional for Unix-like Systems):

```bash
chmod +x SETn3270.py
```

### Usage

#### Launching the Tool

To start the SETn3270 emulator, navigate to the project directory and execute the script:

```bash
python3 SETn3270.py --host <MAINFRAME_HOST> --port <PORT_NUMBER> [--ssl]
```

**Parameters:**

- `--host`: IP address or hostname of the TN3270 server.
- `--port`: Port number to connect to (default is typically `23`).
- `--ssl`: Optional flag to enable SSL/TLS for secure connections.

**Example:**

```bash
python3 SETn3270.py --host mainframe.example.com --port 23 --ssl
```

#### Modifying TSO Screens

SETn3270 allows users to modify specific elements on the TSO screen, such as replacing default messages with custom text.

**Steps:**

1. **Identify the Target Phrase:**
   - Locate the CP037-encoded hexadecimal sequence representing the phrase you wish to modify (e.g., `"DEFCON 23"`).

2. **Run the Modification Script:**
   - Use the provided `modify_defcon.py` script to replace the target phrase.
   - Follow the prompts to input the new phrase.

3. **Generate Custom Hex Encoded Characters:**
   - Utilize **ChatGPT** to obtain CP037 hex-encoded characters for your custom front screen messages, similar to the "SIGHBERBANK" example.
   - **Example Interaction with ChatGPT:**
     ```python
     User: What is the CP037 hex representation of "SIGHBERBANK"?
     ChatGPT: The CP037 hex representation of "SIGHBERBANK" is E2C9C7C8C2C5D2C2C1D5D2.
     ```

4. **Apply Changes:**
   - The script will output the modified hex lines, which can be integrated back into SETn3270 or used as needed.

**Example:**

```bash
python3 modify_defcon.py
```

*Follow the on-screen prompts to input your new phrase.*

#### File Operations

SETn3270 supports both ASCII and binary file transfers between the emulator and the mainframe.

**Sending Files:**

```python
tn.send_binary_file(dataset="USER.DATA", filename="localfile.bin")
```

**Receiving Files:**

```python
tn.get_binary_file(dataset="USER.DATA", filename="downloadedfile.bin")
```

*Ensure proper permissions and dataset names are used.*

#### Sending Commands

Automate sending of PF keys and commands to navigate or execute operations on the mainframe.

**Sending a PF Key:**

```python
tn.send_pf(1)  # Sends PF1
```

**Sending an Enter Key:**

```python
tn.send_enter()
```

*Additional command sequences can be scripted as needed.*

### Features

- **CP037 Encoding:** Accurate representation and manipulation of EBCDIC-encoded data.
- **Screen Modification:** Dynamically alter TSO screen content based on user input.
- **Secure Connections:** Optional SSL/TLS support for encrypted communications.
- **File Transfer Support:** Handle both ASCII and binary file transfers seamlessly.
- **Automated Command Execution:** Script PF keys and other commands for automated interactions.
- **Structured Fields Handling:** Support for complex TN3270 structured fields.
- **Robust Error Handling:** Comprehensive mechanisms to handle unexpected scenarios gracefully.
- **Logging and Debugging:** Configurable logging levels for monitoring and troubleshooting.
- **Integration with ChatGPT:** Easily obtain CP037 hex-encoded characters for custom front screens.

### Benefits

- **Automation:** Streamline repetitive tasks on mainframe systems through scripting.
- **Customization:** Tailor TSO screens to display relevant information or misleading data.
- **Security Testing:** Assess the resilience of mainframe systems against unauthorized interactions.
- **Flexibility:** Adaptable to various use cases, from administrative tasks to security applications.
- **Efficiency:** Enhanced performance through Python 3 optimizations and asynchronous operations.

### Risks

- **Buffer Overflows:** Improper handling of hex string modifications can lead to buffer misalignments, potentially causing application crashes or vulnerabilities.
- **Security Vulnerabilities:** If not properly secured, SETn3270 can be exploited to gain unauthorized access or execute malicious commands on mainframe systems.
- **Data Corruption:** Incorrect modifications can corrupt data streams, leading to inconsistent states or data loss.
- **Compliance Issues:** Unauthorized access or manipulation of mainframe systems may violate organizational policies or regulatory requirements.

### Use Cases

#### Penetration Testing

SETn3270 serves as a powerful tool for penetration testers aiming to evaluate the security posture of IBM mainframe environments.

**Applications:**

- **Screen Manipulation:** Alter TSO screens to test the system's response to unexpected or malicious inputs.
- **Automated Exploits:** Script automated sequences to probe for vulnerabilities or weaknesses in mainframe applications.
- **Data Exfiltration Simulation:** Attempt to retrieve sensitive data through simulated attacks to assess data protection measures.

**Benefits:**

- **Comprehensive Assessment:** Gain deep insights into the security mechanisms of mainframe systems.
- **Customization:** Tailor tests to specific mainframe configurations and security policies.
- **Efficiency:** Automate repetitive testing tasks, saving time and resources.

#### Honeypot Deployment

Incorporating SETn3270 into honeypot setups can attract and analyze malicious activities targeting mainframe environments.

**Applications:**

- **Simulated Environments:** Create realistic mainframe interfaces that mimic genuine TSO screens.
- **Attack Monitoring:** Observe and log attacker behaviors, techniques, and tools used against mainframe systems.
- **Threat Intelligence:** Gather valuable data on emerging threats targeting legacy systems.

**Benefits:**

- **Early Detection:** Identify and respond to attacks targeting mainframe infrastructures.
- **Research Opportunities:** Study attacker methodologies to enhance defensive strategies.
- **Resource Protection:** Safeguard actual mainframe systems by diverting and neutralizing threats in the honeypot environment.

---

## Security Considerations

While SETn3270 is a potent tool for interacting with mainframe systems, it's imperative to adhere to best security practices to prevent misuse or unintended vulnerabilities.

1. **Secure Configuration:**
   - Always enable SSL/TLS for encrypted communications.
   - Use strong, unique credentials for accessing mainframe systems.

2. **Access Control:**
   - Restrict access to SETn3270 to authorized personnel only.
   - Implement role-based access controls to limit functionalities based on user roles.

3. **Regular Updates:**
   - Keep SETn3270 and its dependencies updated to incorporate the latest security patches and features.

4. **Monitoring and Logging:**
   - Enable detailed logging to track all interactions and modifications.
   - Regularly review logs for suspicious activities or anomalies.

5. **Input Validation:**
   - Ensure all user inputs are validated and sanitized to prevent injection attacks or buffer overflows.

6. **Backup and Recovery:**
   - Maintain regular backups of original hex strings and configurations to facilitate recovery in case of corruption or unintended modifications.

---

## Contributing

Contributions are welcome! Please follow the standard GitHub workflow:

1. **Fork the Repository.**
2. **Create a Feature Branch:**
   ```bash
   git checkout -b feature/YourFeature
   ```
3. **Commit Your Changes:**
   ```bash
   git commit -m "Add your descriptive commit message"
   ```
4. **Push to the Branch:**
   ```bash
   git push origin feature/YourFeature
   ```
5. **Open a Pull Request.**

Ensure that your contributions adhere to the project's coding standards and include appropriate documentation and tests.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Contact

For any questions, suggestions, or support, please contact:

- **Email:** your.email@example.com
- **GitHub Issues:** [SETn3270 Issues](https://github.com/yourusername/SETn3270/issues)

---

## Acknowledgments

Special thanks to the open-source community for their invaluable contributions to the development and enhancement of SETn3270. Gratitude also goes to **ChatGPT** for assisting in the refinement and validation of code modifications, ensuring accuracy and efficiency in the tool's functionalities.

---

# Appendix

### CP037 Hex Representation of "SIGHBERBANK"

The string `"SIGHBERBANK"` encoded in CP037 (EBCDIC) is represented as follows:

| Character | CP037 Hex |
|-----------|-----------|
| S         | E2        |
| I         | C9        |
| G         | C7        |
| H         | C8        |
| B         | C2        |
| E         | C5        |
| R         | D2        |
| B         | C2        |
| A         | C1        |
| N         | D5        |
| K         | D2        |

**Complete CP037 Hex for "SIGHBERBANK":** `E2C9C7C8C2C5D2C2C1D5D2`

*Note: Ensure that the new phrase maintains the required length and encoding standards to prevent buffer misalignments or encoding errors.*

---

# Disclaimer

**SETn3270** is intended for authorized use only. Unauthorized access to computer systems is illegal and unethical. The developers and contributors of this project do not endorse or support any malicious activities. Use this tool responsibly and in compliance with all applicable laws and regulations.

---

# References

- [IBM TN3270 Documentation](https://www.ibm.com/docs/en/zos/2.3.0?topic=communications-tn3270)
- [EBCDIC Code Page 037](https://en.wikipedia.org/wiki/EBCDIC#Code_page_layouts)

---

# End of Document

---
```
