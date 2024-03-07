# DNSSECAnalyzer

## Overview
This DNSSEC Analyzer represents a critical tool in the domain of cybersecurity research, specifically tailored for the rigorous analysis of Domain Name System Security Extensions (DNSSEC) implementations across websites of Higher Education Institutions within the European Union. The primary objective of this tool is to systematically gather and evaluate DNS configurations of these institutions to ascertain adherence to DNSSEC.

The analyzer meticulously scans and collects DNS data, providing a comprehensive assessment of whether these institutions employ DNSSEC. More crucially, it delves into the nuances of their DNSSEC configurations, scrutinizing for adherence to current best practices in the field. This encompasses an evaluation of key parameters, detection of any configuration errors, and identification of obsolete or sub-optimal practices that could potentially compromise the security posture of the institutions' online presence.

By leveraging this tool, researchers and cybersecurity professionals can gain invaluable insights into the security landscape of DNS implementations within the academic sector. The outcomes of these analyses not only contribute to enhancing the security of individual institutions but also serve to elevate the overall standard of DNSSEC usage, driving forward the agenda of a safer, more secure internet within the educational domain.

This project stands at the intersection of cybersecurity research and practical application, embodying a commitment to advancing the state of DNS security in an increasingly digitalized academic environment. It is a quintessential example of how targeted, domain-specific cybersecurity tools can yield significant insights and foster a culture of security awareness and excellence in digital infrastructures.

## Configuration
Modify config.yaml to set up the environment, Kafka brokers, and other necessary parameters.

## Building and Running
### Prerequisites
+ Go (version 1.21.0 or later)
+ Docker (for Docker-based deployment)
+ Apache Kafka setup for message handling
### Compiling with Docker
1. Build the Docker image using the provided Dockerfile.
2. Run the Docker container.

## Usage
Run the application to start scanning the specified targets. Results will be processed and managed through Kafka topics.

## Contributing
Contributions to this project are welcome. Please submit pull requests or open issues for any enhancements or bug fixes.