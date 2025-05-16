# Real-Time AI-Driven Intrusion Detection System

## Overview

This project implements a real-time Intrusion Detection System (IDS) utilizing Suricata for network traffic analysis, nDPI for deep packet inspection, an Isolation Forest machine learning model for anomaly detection, and the ELK stack (Elasticsearch, Kibana, Filebeat) for log management and visualization. The entire system is containerized using Docker for ease of deployment and an out-of-the-box experience.

The system is designed to detect various network threats, including common attacks like SYN floods, by analyzing network flow data in real-time and flagging suspicious activities based on the AI model's predictions.

## Features

- **Real-Time Traffic Monitoring**: Suricata captures and inspects network traffic.
- **AI-Driven Anomaly Detection**: An Isolation Forest model identifies anomalous network flows.
- **Configurable Network Interface**: The Suricata monitoring interface can be easily configured.
- **ELK Stack Integration**: Logs and alerts are shipped to Elasticsearch for analysis and visualized in Kibana.
- **Dockerized Deployment**: All components are containerized for straightforward setup.
- **Sample Data Included**: Comes with sample benign and attack PCAP/CSV files for immediate testing and model training.
- **Basic Kibana Dashboard**: A template for a Kibana dashboard is provided to visualize detected anomalies.

## Project Structure

```
real-time-ai-ids/
├── docker/                 # Docker configurations
│   ├── docker-compose.yml  # Defines all services
│   └── Dockerfile.suricata # Builds Suricata with nDPI and rules
│   └── custom.rules        # Custom Suricata rules (e.g., SYN flood)
├── configs/                # Service configurations
│   ├── suricata.yaml       # Suricata configuration (EVE JSON, nDPI, rules)
│   └── filebeat.yml        # Filebeat configuration (ships Suricata logs to ES)
├── scripts/                # Python scripts
│   ├── train_model.py      # Trains the Isolation Forest model
│   ├── detect_anomalies.py # Performs real-time anomaly detection
│   ├── requirements.txt    # Python dependencies
│   ├── flows_benign.csv    # Sample benign flow data for training
│   └── flows_attack.csv    # Sample attack flow data for validation
├── pcap/                   # Sample PCAP files
│   ├── sample_benign.pcap  # Sample benign traffic
│   └── sample_attack.pcap  # Sample attack traffic (SYN flood)
├── logs/                   # Placeholder for Suricata logs (mounted in Docker)
├── dashboards/             # Kibana dashboard templates
│   └── suricata_anomalies.ndjson # Basic anomaly dashboard export
├── docs/                   # Project documentation
│   ├── README.md           # This file
│   └── report.md           # Detailed project report
└── .gitignore              # Specifies intentionally untracked files
```

## Setup and Usage

### Prerequisites

- Docker and Docker Compose installed on your system.
- Git (for cloning the repository).

### Installation

1.  **Clone the Repository**:

    ```bash
    # git clone <repository_url>
    # cd real-time-ai-ids
    ```

2.  **Configure Network Interface (Optional)**:
    The default network interface for Suricata is `eth0`. You can change this by setting the `SURICATA_INTERFACE` environment variable. For example, create a `.env` file in the `real-time-ai-ids/docker/` directory with the following content:

    ```env
    SURICATA_INTERFACE=your_network_interface
    ```

    Alternatively, you can set it when running `docker-compose`:

    ```bash
    SURICATA_INTERFACE=your_network_interface docker-compose -p real_time_ai_ids up -d
    ```

3.  **Build and Start Services**:
    Navigate to the `docker` directory and run Docker Compose:
    ```bash
    cd docker/
    docker-compose -p real_time_ai_ids up -d --build
    ```
    This will build the custom Suricata image (which includes downloading Emerging Threats Open rules) and start all services (Elasticsearch, Kibana, Filebeat, Suricata, and the detection script).

### Initial Setup and Model Training

1.  **Wait for ELK Stack**: Allow a few minutes for Elasticsearch and Kibana to initialize fully.

    - Elasticsearch will be available at `http://localhost:9200`.
    - Kibana will be available at `http://localhost:5601`.
    - Default credentials for Elasticsearch/Kibana are `elastic` / `changeme`.

2.  **Train the AI Model**:
    The `train_model.py` script uses the provided `flows_benign.csv` and `flows_attack.csv` sample files located in the `scripts/` directory to train the `ids_model.pkl`. This model is automatically used by the `detection` service.
    The training is part of the `detection` service startup in `docker-compose.yml` but if you need to retrain it or train it manually (e.g. after providing your own CSVs):
    ```bash
    docker-compose -p real_time_ai_ids exec detection python train_model.py
    ```
    The sample CSVs are illustrative. For production use, you should generate these from larger, representative PCAP datasets using a tool like `ndpiReader` (which is installed in the Suricata Docker image).
    Example (run inside the Suricata container or on a host with ndpiReader and PCAPs):
    ```bash
    # To access ndpiReader inside the Suricata container:
    # docker-compose -p real_time_ai_ids exec suricata bash
    # cd /pcap # Assuming your PCAPs are mounted here or copied
    # ndpiReader -i your_benign_traffic.pcap -C /app/flows_benign.csv # Output to scripts dir
    # ndpiReader -i your_attack_traffic.pcap -C /app/flows_attack.csv # Output to scripts dir
    ```
    Then copy these CSVs to the `scripts` directory on your host if generated outside, or ensure paths are correct for the `train_model.py` script if run inside a container.

### Real-Time Detection

The `detection` service automatically starts the `detect_anomalies.py` script. This script continuously queries Elasticsearch for new flow data from Suricata, processes it using the trained `ids_model.pkl`, and indexes any detected anomalies into a new Elasticsearch index named `suricata-anomalies`.

### Viewing Results in Kibana

1.  Access Kibana at `http://localhost:5601`.
2.  Log in with `elastic` / `changeme`.
3.  **Import Dashboard (Optional)**:
    - Navigate to "Stack Management" > "Saved Objects".
    - Click "Import" and upload the `dashboards/suricata_anomalies.ndjson` file.
    - This provides a basic dashboard to visualize data from the `suricata-anomalies` index.
4.  **Explore Data**:
    - You can create your own visualizations and dashboards in Kibana.
    - Explore the `filebeat-*` indices for raw Suricata logs and the `suricata-anomalies` index for detected anomalies.

## Troubleshooting

- **Elasticsearch Fails to Start**: Check Docker logs (`docker-compose -p real_time_ai_ids logs elasticsearch`). Common issues include insufficient memory. You might need to increase `ES_JAVA_OPTS` in `docker-compose.yml` (e.g., to `-Xms1g -Xmx1g`) if your system has enough RAM.
- **No Logs in Kibana / `suricata-anomalies` index empty**:
  - Verify Suricata is running and capturing traffic on the correct interface (`docker-compose -p real_time_ai_ids logs suricata`).
  - Check Filebeat logs (`docker-compose -p real_time_ai_ids logs filebeat`) for errors shipping logs to Elasticsearch.
  - Ensure `eve.json` is being populated in `real-time-ai-ids/logs/`.
  - Check `detection` service logs (`docker-compose -p real_time_ai_ids logs detection`) for errors in the anomaly detection script.
- **Suricata Not Capturing Traffic**: Ensure the `SURICATA_INTERFACE` is correctly set to an active network interface with traffic. Use tools like `tcpdump` on the host or inside the Suricata container to verify traffic on the interface.
- **Authentication Errors**: Confirm the default credentials (`elastic`/`changeme`) are used consistently if not changed. If you change them, update `docker-compose.yml`, `filebeat.yml`, and `detect_anomalies.py` accordingly.

## Further Development

- **Enhance Anomaly Detection Model**: Experiment with different features, models, or hyperparameter tuning.
- **Expand Suricata Rules**: Integrate more comprehensive rule sets.
- **Improve Kibana Dashboards**: Create more detailed and insightful visualizations.
- **Alerting Mechanisms**: Implement real-time alerting (e.g., email, Slack) for critical anomalies.

For a more detailed explanation of the project's design, components, and implementation, please refer to `docs/report.md`.
