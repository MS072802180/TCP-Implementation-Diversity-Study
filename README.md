TCP Implementation Diversity Study
==================================

Author: MS072802180
Date: 2026/5

Overview
--------

This repository contains code and documentation for a passive measurement study
of TCP implementation diversity. The study analyzes 56,511 TCP handshakes
extracted from 25 pcap files captured in 2014. The analysis includes option
adoption rates, window scale diversity, MSS diversity, operating system
inference from TTL values, and the performance security trade off.

The original study design called for active probing of live servers. Due to
network access limitations and time constraints, the project pivoted to passive
analysis of existing pcap files. The mathematical models and analysis methods
remained unchanged.

Repository Structure
--------------------

tcp_diversity_study/
├── README.txt
├── paper.tex
├── references.bib
├── figures/
│   ├── 01_option_adoption.png
│   ├── 02_window_scale_distribution.png
│   ├── 03_mss_distribution.png
│   ├── 07_ttl_os_distribution.png
│   ├── 09_performance_security_tradeoff.png
│   └── protocol_distribution.png
├── code/
│   ├── extract_handshakes.py
│   ├── analyze_tcp.py
│   └── udp_analysis.py
└── data/
    └── (pcap files not included due to size)

Requirements
------------

The code requires Python 3.8 or higher and the following packages:

- scapy (packet manipulation)
- pandas (data analysis)
- numpy (numerical operations)
- matplotlib (visualization)
- seaborn (statistical visualizations)
- scipy (statistical tests)

Installation
------------

Install the required packages using pip:

pip install scapy pandas numpy matplotlib seaborn scipy

Usage
-----

1. Place pcap files in the data/ directory.

2. Extract TCP handshakes:

   python code/extract_handshakes.py

3. Run the main analysis:

   python code/analyze_tcp.py

4. Generate figures:

   The analysis script automatically generates figures in the figures/
   directory.

Key Findings
------------

- Timestamps appeared in only 15.7 percent of handshakes
- Window scale 7 dominated at 62.7 percent of WS enabled cases
- Thirteen distinct window scale values observed (0 to 12)
- Nineteen distinct MSS values observed
- 1400 byte MSS dominated over the expected 1460 bytes
- Linux based servers made up 80.4 percent of responses
- Correlation between throughput and security risk was 0.567
- UDP had no configurable options across 582,670 packets

Limitations
-----------

- Data is from 2014 and may not reflect current practices
- IP addresses are anonymized
- No server categorization by function (CDN, cloud, academic, IoT) is possible
- Passive analysis observes only naturally occurring handshakes

Reproducibility
---------------

All code is provided for reproducibility. The specific pcap files used are
publicly available from the sources cited in the paper. Due to file size,
they are not included in this repository.

Contact
-------

For questions or issues, contact [Your Email Address].

License
-------

[Apache 2.0]
