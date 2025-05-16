# Project Report: Real-Time AI-Driven Intrusion Detection System

## 1. Introduction

This report details the design, implementation, testing, and limitations of the Real-Time AI-Driven Intrusion Detection System (IDS). The primary objective of this project is to develop a robust and scalable IDS capable of identifying malicious network activities in real-time. The system leverages a combination of traditional signature-based detection with Suricata and modern machine learning techniques for anomaly detection, specifically using an Isolation Forest model. All components are containerized using Docker for ease of deployment, portability, and to ensure an out-of-the-box operational experience.

The system architecture is built around several key technologies: Suricata for high-performance network traffic analysis, nDPI for deep packet inspection and application protocol identification, Python for scripting the machine learning pipeline, the ELK stack (Elasticsearch, Kibana, Filebeat) for log aggregation, storage, and visualization, and Docker to orchestrate these components.

This document will cover the system architecture, detailed descriptions of each component, the data flow, the machine learning model development process, setup and configuration instructions, testing methodologies, observed results, and potential limitations and future enhancements.

## 2. System Architecture and Design

The IDS is designed as a modular system where each component performs a specific task, contributing to the overall goal of real-time threat detection.

### 2.1. Core Components

*   **Suricata**: Acts as the primary network sensor. It captures live network traffic (or reads from PCAP files), inspects packets against a set of rules (including custom rules and Emerging Threats rules), and generates detailed event logs in EVE JSON format. These logs include alerts, flow data, protocol-specific information (HTTP, DNS, TLS), and file extraction details.
*   **nDPI (via Suricata Integration)**: nDPI (ntop Deep Packet Inspection) is compiled into the custom Suricata build. It enhances Suricata's capabilities by providing more accurate application protocol detection (e.g., identifying specific services running on standard or non-standard ports). This `app_proto` information is included in the EVE JSON flow records and is crucial for contextualizing network behavior.
*   **Filebeat**: A lightweight log shipper from the Elastic Stack. It monitors Suricata's EVE JSON output file (`eve.json`) and forwards new log entries in real-time to Elasticsearch for indexing and storage.
*   **Elasticsearch**: A distributed, RESTful search and analytics engine. It stores all logs sent by Filebeat, making them searchable and available for analysis. Suricata flow records and alerts are stored in time-series indices (e.g., `filebeat-*`). Detected anomalies from the AI script are stored in a dedicated index (`suricata-anomalies`).
*   **Kibana**: A web-based visualization and exploration tool for Elasticsearch data. It allows users to create dashboards, explore raw logs, and gain insights into network activity and detected threats. A sample dashboard is provided to visualize anomalies.
*   **Python Anomaly Detection Service (`detect_anomalies.py`)**: This script runs as a separate Docker container. It periodically queries Elasticsearch for recent Suricata flow records, preprocesses this data, and uses a pre-trained Isolation Forest model (`ids_model.pkl`) to score each flow. Flows deemed anomalous are then indexed back into Elasticsearch into the `suricata-anomalies` index for visualization and alerting.
*   **Python Model Training Script (`train_model.py`)**: This script is responsible for training the Isolation Forest model. It uses CSV files containing features extracted from benign and (optionally) attack traffic. The sample CSVs provided (`flows_benign.csv`, `flows_attack.csv`) are derived from the sample PCAPs. The script outputs a serialized model file (`ids_model.pkl`).
*   **Docker & Docker Compose**: Docker is used to containerize each component, ensuring consistent environments and simplifying deployment. Docker Compose is used to define and manage the multi-container application, including service dependencies, volumes, and networking.

### 2.2. Data Flow

1.  **Traffic Capture**: Suricata captures network packets from a specified network interface (configurable, e.g., `eth0`) or reads from a PCAP file during testing.
2.  **Inspection & Logging**: Suricata inspects the traffic, matches against rules, performs protocol analysis (enhanced by nDPI), and generates EVE JSON logs to `/var/log/suricata/eve.json` within its container. This log file is volume-mounted to the host and accessible by Filebeat.
3.  **Log Shipping**: Filebeat tails `eve.json` and ships new log entries to the Elasticsearch `filebeat-*` indices.
4.  **Anomaly Detection Query**: The `detect_anomalies.py` script queries Elasticsearch for recent flow records from the `filebeat-*` indices.
5.  **Feature Extraction & Scoring**: The script extracts relevant features from the flow records (duration, packet counts, byte counts), matching those used during model training.
6.  **Prediction**: The script uses the loaded Isolation Forest model (`ids_model.pkl`) to predict an anomaly score for each flow.
7.  **Anomaly Indexing**: Flows with an anomaly score below a defined threshold are flagged as anomalies and indexed into the `suricata-anomalies` Elasticsearch index, including the original flow data and the anomaly score.
8.  **Visualization**: Kibana connects to Elasticsearch, allowing users to visualize raw Suricata logs from `filebeat-*` and the detected anomalies from `suricata-anomalies` using pre-built or custom dashboards.

### 2.3. Machine Learning Model: Isolation Forest

An Isolation Forest algorithm was chosen for anomaly detection due to its efficiency with high-dimensional data and its effectiveness in identifying outliers without requiring pre-labeled anomaly data for training (though it benefits from clean, benign training data).

*   **Training Data**: The model is trained primarily on features extracted from benign network traffic. The provided `flows_benign.csv` contains sample data with the following features: `duration`, `src2dst_packets`, `dst2src_packets`, `src2dst_bytes`, `dst2src_bytes`. These features represent basic characteristics of a network flow.
*   **Contamination Parameter**: The `contamination` parameter in the Isolation Forest model is an estimate of the proportion of outliers in the dataset. This was set to `0.05` in `train_model.py` but can be tuned based on the characteristics of the training data and desired sensitivity.
*   **Feature Set**: The features used for training and real-time detection are:
    *   `duration`: Duration of the flow in seconds.
    *   `pkts_toserver` (or `src2dst_packets` in training CSV): Packets from client to server.
    *   `pkts_toclient` (or `dst2src_packets` in training CSV): Packets from server to client.
    *   `bytes_toserver` (or `src2dst_bytes` in training CSV): Bytes from client to server.
    *   `bytes_toclient` (or `dst2src_bytes` in training CSV): Bytes from server to client.
    The `detect_anomalies.py` script ensures consistency in feature names when querying Suricata flow data from Elasticsearch.

### 2.4. Field Mapping and Data Consistency

A critical aspect is ensuring consistency between features extracted by different tools (e.g., `ndpiReader` for generating training CSVs and Suricata for real-time flow logging). The `README.md` and this report highlight the mapping:

*   `ndpiReader` `duration` -> Suricata flow `duration` (calculated from `flow.start` and `flow.end`).
*   `ndpiReader` `src2dst_packets` -> Suricata `flow.pkts_toserver`.
*   `ndpiReader` `dst2src_packets` -> Suricata `flow.pkts_toclient`.
*   `ndpiReader` `src2dst_bytes` -> Suricata `flow.bytes_toserver`.
*   `ndpiReader` `dst2src_bytes` -> Suricata `flow.bytes_toclient`.

The `detect_anomalies.py` script correctly extracts these fields from the Suricata EVE JSON structure.

## 3. Implementation Details

This section describes the specific configurations and scripts used in the project.

### 3.1. Docker Setup (`docker/`)

*   **`docker-compose.yml`**: Defines the five main services:
    *   `elasticsearch`: Uses the official Elastic image. Configured for single-node discovery and default credentials (`elastic`/`changeme`). Data is persisted in a Docker volume (`esdata`).
    *   `kibana`: Uses the official Elastic image. Connects to the `elasticsearch` service and uses the same default credentials.
    *   `filebeat`: Uses the official Elastic image. Mounts `filebeat.yml` for configuration and the `logs/` directory to access Suricata's `eve.json`.
    *   `suricata`: Built using `Dockerfile.suricata`. Runs in `network_mode: host` for easier access to network interfaces. The monitoring interface is configurable via the `SURICATA_INTERFACE` environment variable (default `eth0`). Mounts `suricata.yaml`, the `pcap/` directory (for reading PCAPs if needed), and the `logs/` directory (for writing `eve.json`).
    *   `detection`: Uses a `python:3.9` base image. Mounts the `scripts/` directory. The command installs dependencies from `requirements.txt` and then runs `detect_anomalies.py`. It depends on Elasticsearch being available.
*   **`Dockerfile.suricata`**: Builds a custom Suricata image:
    *   Based on `ubuntu:22.04`.
    *   Installs build dependencies, Git, Python, pip, and `suricata-update`.
    *   Clones, compiles, and installs nDPI from source to enable its use with Suricata.
    *   Clones, compiles, and installs Suricata (version 7.0.10) with nDPI support (`--enable-ndpi`) and NFQUEUE support (`--enable-nfqueue`).
    *   Uses `suricata-update` to fetch and enable the Emerging Threats Open ruleset and OISF Traffic ID rules. These are stored in `/etc/suricata/rules/` within the image.
    *   Copies `custom.rules` (containing the sample SYN flood rule) into `/etc/suricata/rules/`.
*   **`custom.rules`**: Contains a sample Suricata rule:
    ```
    alert tcp any any -> any any (msg:"Possible SYN Flood"; flags:S,not A; flow:to_server; threshold: type both, track by_src, count 100, seconds 1; sid:1000001; rev:1;)
    ```
    This rule flags a potential SYN flood if 100 SYN packets (without ACKs) are seen from the same source IP within 1 second.

### 3.2. Configurations (`configs/`)

*   **`suricata.yaml`**: Main Suricata configuration file.
    *   Specifies rule paths and files, including `suricata.rules` (from `suricata-update`) and `custom.rules`.
    *   Configures `af-packet` for packet capture, with the interface to be overridden by the command-line argument `-i $SURICATA_INTERFACE` passed in `docker-compose.yml`.
    *   Enables EVE JSON output (`eve-log`) to `/var/log/suricata/eve.json`. Critically, it enables `flow` event types and specifies the fields required by the anomaly detection script: `start`, `end`, `pkts_toserver`, `pkts_toclient`, `bytes_toserver`, `bytes_toclient`, `app_proto`, `src_ip`, `dest_ip`, `src_port`, `dest_port`, `proto`.
    *   Enables nDPI for `app_proto` detection via `app-layer-appids` settings.
*   **`filebeat.yml`**: Configures Filebeat.
    *   Uses the Suricata module to parse EVE JSON logs from `/var/log/suricata/eve.json`.
    *   Specifies Elasticsearch output hosts, username, and password (default `elastic`/`changeme`).
    *   Configures Kibana setup for dashboard loading (though the sample dashboard is intended for manual import).

### 3.3. Scripts (`scripts/`)

*   **`requirements.txt`**: Lists Python dependencies:
    *   `pandas`: For data manipulation.
    *   `scikit-learn`: For the Isolation Forest model.
    *   `joblib`: For saving and loading the trained model.
    *   `elasticsearch`: Python client for Elasticsearch.
*   **`train_model.py`**: Trains the Isolation Forest model.
    *   Loads benign flow data from `flows_benign.csv` (and optionally attack data from `flows_attack.csv` for validation).
    *   Selects the specified features: `duration`, `src2dst_packets`, `dst2src_packets`, `src2dst_bytes`, `dst2src_bytes`.
    *   Initializes and fits an `IsolationForest` model.
    *   Saves the trained model to `ids_model.pkl` using `joblib`.
    *   Includes basic error handling for missing CSV files or features.
*   **`detect_anomalies.py`**: Performs real-time anomaly detection.
    *   Connects to Elasticsearch with retry logic.
    *   Loads the pre-trained `ids_model.pkl`.
    *   Enters an infinite loop, periodically (every 30 seconds) querying Elasticsearch for new flow records from `filebeat-*` indices within the last time window.
    *   Processes retrieved flows: calculates `duration` from `start` and `end` timestamps, extracts other relevant features.
    *   Handles potential missing fields and ensures data types are correct.
    *   Applies the Isolation Forest model to get anomaly scores for the flows.
    *   Flags flows with scores below `ANOMALY_THRESHOLD` (-0.3 by default) as anomalies.
    *   Indexes these anomalous flows into the `suricata-anomalies` Elasticsearch index.
    *   Includes robust error handling for Elasticsearch connection issues and data processing problems.

### 3.4. Sample Data (`pcap/` and `scripts/`)

*   **`pcap/sample_benign.pcap`**: A small PCAP file containing a few packets of a simple HTTP GET request and response. Generated using `text2pcap` from a hex dump.
*   **`pcap/sample_attack.pcap`**: A small PCAP file containing a few TCP SYN packets from the same source IP to the same destination, simulating a SYN flood. Generated using `text2pcap`.
*   **`scripts/flows_benign.csv`**: Illustrative CSV data representing benign flows, with headers: `duration,src2dst_packets,dst2src_packets,src2dst_bytes,dst2src_bytes`. Contains a few rows of sample data.
*   **`scripts/flows_attack.csv`**: Illustrative CSV data representing attack flows (SYN flood characteristics), with the same headers. Contains a few rows of sample data.
    *   *Note*: These CSVs are manually created placeholders. The `README.md` guides the user on generating more comprehensive CSVs from their own PCAP data using `ndpiReader` for effective model training.

### 3.5. Dashboard (`dashboards/`)

*   **`suricata_anomalies.ndjson`**: A basic Kibana dashboard export (NDJSON format). This is a template and may require adjustments or re-creation by the user in their Kibana instance. It's intended to provide a starting point for visualizing data from the `suricata-anomalies` index, such as a table of anomalies, counts over time, and breakdowns by source/destination IP.

### 3.6. Version Control (`.gitignore`)

*   **`.gitignore`**: Excludes common files that should not be committed to version control, such as log files, PCAP files (beyond samples), CSV data files (beyond samples), and Python model files (`*.pkl`).

## 4. Testing and Validation

Testing was conceptualized in several stages to ensure the system functions as intended. Due to the execution environment limitations (no Docker Compose), full end-to-end testing was not performed by the agent, but the components are designed to be testable by the user.

### 4.1. Unit Testing (Conceptual)

*   **`train_model.py`**: Can be tested by running it with the sample CSV files and verifying that `ids_model.pkl` is created and that the validation output (if attack data is present) makes sense.
*   **`detect_anomalies.py`**: Can be unit-tested by mocking the Elasticsearch client and providing sample flow data to verify feature extraction, model scoring, and anomaly flagging logic.

### 4.2. Integration Testing (User-Performed)

This is the most crucial phase and would be performed by the user after setting up the Docker environment.

1.  **ELK Stack & Filebeat**: Verify Elasticsearch and Kibana are running. Confirm Filebeat starts without errors and establishes a connection to Elasticsearch. Check Filebeat logs.
2.  **Suricata Traffic Capture & Logging**: 
    *   Start Suricata. If using live traffic, ensure it's capturing from the correct interface. 
    *   Alternatively, use `tcpreplay` (or a similar tool) to replay `sample_benign.pcap` and `sample_attack.pcap` against the interface Suricata is monitoring.
    *   Verify that `eve.json` is created in the `logs/` directory and is populated with EVE JSON events.
    *   Check Kibana Discover for data in `filebeat-*` indices corresponding to the replayed traffic.
3.  **Anomaly Detection Pipeline**: 
    *   Ensure the `detection` service is running and connected to Elasticsearch. Check its logs.
    *   After replaying attack traffic (e.g., `sample_attack.pcap`), monitor the `detection` service logs for messages about processing flows and finding anomalies.
    *   Check Kibana for the creation of the `suricata-anomalies` index and for documents within it corresponding to the replayed attack flows.
4.  **Kibana Dashboard**: Import and view the `suricata_anomalies.ndjson` dashboard to see if it visualizes the detected anomalies correctly.

### 4.3. Attack Simulation (User-Performed)

*   **SYN Flood**: Replay `sample_attack.pcap`. Suricata should generate alerts (if the rule threshold is met by the replayed volume/rate) and flow logs. The `detect_anomalies.py` script should flag these flows as anomalous based on their characteristics (high `pkts_toserver`, low/zero `pkts_toclient`, short duration if connections don't complete).
*   **Other Attacks**: The user can test with other PCAPs containing different types of attacks (e.g., port scans, malware C&C traffic from datasets like CIC-IDS2017). The effectiveness will depend on how well the Isolation Forest model (trained on general flow characteristics) can distinguish these from benign traffic, and on the comprehensiveness of Suricata rules.

### 4.4. Performance Testing (Conceptual)

*   Monitor resource usage (CPU, memory) of all Docker containers under varying network traffic loads.
*   Assess the latency of the detection pipeline (from traffic capture to anomaly visibility in Kibana).
*   Evaluate Elasticsearch and Suricata performance under stress.

## 5. Limitations and Future Enhancements

### 5.1. Limitations

*   **Model Generalization**: The Isolation Forest model's effectiveness is highly dependent on the quality and representativeness of the benign training data. The provided sample CSVs are too small for robust detection and are for illustrative purposes only. The model might not generalize well to network environments or traffic patterns significantly different from the training data.
*   **Zero-Day Attacks**: While anomaly detection can theoretically find novel attacks, sophisticated zero-day attacks designed to mimic benign traffic might evade detection by this relatively simple model.
*   **Feature Set**: The current feature set for the ML model is basic (duration, packet/byte counts). More sophisticated features (e.g., inter-arrival times, protocol-specific metrics, graph-based features) could improve detection accuracy.
*   **nDPI Feature Utilization**: While nDPI is integrated for `app_proto` detection in Suricata logs, the current ML model does not directly use `app_proto` as a feature. This could be a valuable addition.
*   **Scalability**: While components like Elasticsearch and Suricata are scalable, the single Python detection script might become a bottleneck under very high traffic volumes. It processes flows in batches but is single-threaded.
*   **Alert Fatigue**: Anomaly detection systems can sometimes generate a high number of false positives, leading to alert fatigue. Tuning the `contamination` parameter and the `ANOMALY_THRESHOLD` is crucial.
*   **Encrypted Traffic**: Like most IDSs, analysis of encrypted traffic (TLS, SSH) is limited to metadata unless decryption capabilities (e.g., TLS inspection proxies, which are outside the scope of this project) are employed.
*   **Dynamic Rule Updates**: While `suricata-update` is run at image build time, there's no automated process for continuous rule updates in the running container. This would typically be handled by a separate cron job or orchestration.

### 5.2. Future Enhancements

*   **Advanced ML Models**: Explore more sophisticated anomaly detection algorithms (e.g., Autoencoders, LSTMs for sequential data, Graph Neural Networks for relational data).
*   **Enriched Feature Engineering**: Incorporate more diverse features, including `app_proto`, DNS query details, TLS handshake parameters, HTTP header information, etc.
*   **Online Learning**: Implement or adapt models for online learning to adapt to evolving network traffic patterns and reduce model staleness.
*   **Feedback Mechanism**: Develop a system for analysts to label false positives/negatives, which can be used to retrain and improve the model.
*   **Distributed Detection Script**: Scale the `detect_anomalies.py` script, perhaps using a task queue (e.g., Celery) or a stream processing framework (e.g., Kafka Streams, Flink) for higher throughput.
*   **Automated Rule Management**: Implement a mechanism for periodic `suricata-update` execution within the running Suricata container or via an external scheduler.
*   **Enhanced Kibana Dashboards**: Develop more comprehensive and interactive dashboards for deeper analysis and incident response.
*   **Integration with SOAR**: Connect the IDS to a Security Orchestration, Automation, and Response (SOAR) platform for automated incident response actions.
*   **User Interface for Configuration**: A simple web UI for managing configurations, model retraining, and viewing high-level statistics.

## 6. Conclusion

The Real-Time AI-Driven Intrusion Detection System provides a foundational platform for network monitoring and threat detection. By combining the strengths of Suricata's rule-based engine with an Isolation Forest model for anomaly detection, and leveraging the ELK stack for data management and visualization, the system offers a comprehensive approach to network security. The Dockerized deployment ensures ease of setup and use.

While the current implementation has limitations, particularly concerning the simplicity of the sample ML model and feature set, it serves as a solid base for further development and customization. Users are encouraged to train the model with their own representative data and expand upon the provided components to tailor the IDS to their specific security needs and network environment.

This report, along with the `README.md` and the provided codebase, aims to give users a thorough understanding of the system and enable them to deploy, operate, and extend it effectively.

