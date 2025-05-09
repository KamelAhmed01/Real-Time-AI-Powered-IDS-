# Real-Time AI-Powered IDS

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) ![Python Version](https://img.shields.io/badge/python-3.x-blue.svg) ![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)

A robust, containerized Intrusion Detection System that leverages Suricata for real-time network traffic analysis, an Isolation Forest machine learning model for AI-driven anomaly detection, and the ELK stack for comprehensive logging and visualization.

---

## ✨ Key Objectives

- **Real-Time IDS:** Continuously monitor network traffic and identify threats as they happen.
- **AI-Driven Detection:** Employ machine learning (Isolation Forest) to uncover malicious activities and anomalies beyond signature-based methods.
- **Log Analysis & Visualization:** Analyze packet captures and logs, with results visualized in Kibana dashboards.

---

## 🚀 Getting Started

### Prerequisites

- **Linux Environment:** Ubuntu 22.04 LTS is recommended.
- **Docker & Docker Compose:** Ensure they are installed and operational. (Min. 8GB RAM allocated to Docker is advisable).
- **Python 3.x & Pip:** For running local scripts (model training, anomaly detection).
- **Git:** For cloning the repository.
- **PCAP Files:** For training the ML model (e.g., from CIC-IDS2017 or your own captures). You will need `train_benign.pcap`, `val_benign.pcap`, and `val_attack.pcap` (or similar, adjust script paths if names differ).
- **`ndpiReader` Tool:** This tool (from the [nDPI GitHub](https://github.com/ntop/nDPI) project) is required to convert your PCAP files into the CSV flow format needed for training the model. It must be installed separately.

### Repository Structure

```
real-time-ai-ids/
├── docker/              # Docker configurations (Dockerfile.suricata, docker-compose.yml)
├── configs/             # Service configurations (suricata.yaml, custom.rules, filebeat.yml)
├── scripts/             # Python scripts (train_model.py, detect_anomalies.py, requirements.txt)
├── pcap/                # Placeholder for PCAP files and generated CSVs (add .gitkeep)
├── logs/                # Placeholder for Suricata logs (add .gitkeep)
├── dashboards/          # Kibana dashboard exports (suricata_anomalies.ndjson)
├── docs/                # Project documentation (README.md, report.md)
└── .gitignore           # Specifies intentionally untracked files
```

### Installation & Setup

1.  **Clone the Repository:**

    ```bash
    git clone <your-repository-url>
    cd real-time-ai-ids
    ```

2.  **Prepare Training Data (PCAP to CSV):**

    - Place your PCAP files (`train_benign.pcap`, `val_benign.pcap`, `val_attack.pcap`) into the `pcap/` directory.
    - Use `ndpiReader` to generate CSV flow files. For example:
      ```bash
      # Ensure ndpiReader is in your PATH or use the full path to it
      # Execute these from within the real-time-ai-ids/pcap/ directory or adjust paths
      ndpiReader -i train_benign.pcap -C flows_benign.csv
      ndpiReader -i val_benign.pcap -C flows_val_benign.csv
      ndpiReader -i val_attack.pcap -C flows_attack.csv
      ```
    - Ensure the generated `flows_benign.csv`, `flows_val_benign.csv`, and `flows_attack.csv` are in the `pcap/` directory.

3.  **Install Python Dependencies & Train the Model:**

    - Navigate to the `scripts/` directory.
    - Install required Python packages:
      ```bash
      pip3 install -r requirements.txt
      ```
    - Train the Isolation Forest model:
      ```bash
      python3 train_model.py
      ```
      This will create `ids_model.pkl` and `optimal_threshold.txt` in the `scripts/` directory. The `detect_anomalies.py` script will automatically use the threshold from `optimal_threshold.txt`.

4.  **Build and Launch Docker Containers:**

    - Navigate to the `docker/` directory.
    - Run Docker Compose:
      ```bash
      sudo docker-compose up -d --build
      ```
      This will build the custom Suricata image and start Elasticsearch, Kibana, Filebeat, and Suricata services.

5.  **Configure Filebeat and Kibana:**

    - Wait a minute or two for Elasticsearch and Kibana to fully initialize.
    - Find your Filebeat container ID: `sudo docker ps` (look for the `filebeat` image).
    - Enable the Suricata module in Filebeat:
      ```bash
      sudo docker exec <filebeat_container_id_or_name> filebeat modules enable suricata
      ```
    - Set up Kibana dashboards (this loads default Suricata dashboards):
      ```bash
      sudo docker exec <filebeat_container_id_or_name> filebeat setup --dashboards
      ```
    - Restart Filebeat to apply changes:
      ```bash
      sudo docker-compose restart filebeat # Run from the docker/ directory
      ```

6.  **Start Real-Time Anomaly Detection Script:**
    - Navigate back to the `scripts/` directory.
    - Run the detection script (it will connect to Elasticsearch running in Docker):
      ```bash
      python3 detect_anomalies.py
      ```
      Keep this script running to continuously monitor and detect anomalies.

---

## 🛠️ Usage

- **Kibana:** Access Kibana at `http://localhost:5601` in your browser.
  - Credentials: username `elastic`, password `changeme` (change these in a production environment!).
  - Explore Suricata logs and alerts (e.g., under Discover, or the `[Filebeat Suricata] Events Overview` dashboard).
  - To view AI-detected anomalies, create a new Data View (formerly Index Pattern) in Kibana for `suricata-anomalies*`. Then you can explore these in Discover or build/import a custom dashboard (a placeholder `dashboards/suricata_anomalies.ndjson` is provided; you would typically export your own from Kibana).
- **Suricata Logs:** Raw EVE JSON logs are stored in `logs/eve.json` (mounted from the Suricata container).
- **Anomaly Detection Script:** The `detect_anomalies.py` script will print output to the console, indicating the number of flows processed and anomalies found.

---

## ⚠️ Troubleshooting & Notes

- **Docker Daemon Issues:** If `docker-compose up` fails, ensure your Docker daemon is running correctly and has sufficient permissions. Some environments (like certain sandboxes) might have conflicts (e.g., `iptables/nftables`).
- **Elasticsearch Connection:** If `detect_anomalies.py` can't connect to Elasticsearch:
  - Verify Elasticsearch is running: `sudo docker ps`.
  - Check container logs: `sudo docker logs <elasticsearch_container_id>`.
  - Ensure the hostname `elasticsearch` is resolvable from where you run the script (if not running on the same Docker host network, you might need to expose Elasticsearch differently or adjust connection settings).
- **Resource Usage:** The ELK stack and Suricata can be resource-intensive. Monitor your system resources.
- **`ndpiReader`:** This tool is crucial for generating the training CSVs. Ensure it's correctly installed and used.
- **`optimal_threshold`:** The `train_model.py` script attempts to find an optimal threshold. If validation data is insufficient or problematic, it might default. Manual tuning or better validation data might be needed for optimal performance.
- **Security:** The default Elasticsearch password is `changeme`. **This must be changed for any non-testing deployment.** Refer to Elastic documentation for securing your ELK stack.

---

## 📄 Documentation

For a more in-depth understanding of the project design, architecture, implementation details, and limitations, please refer to the [Project Report](./Project_Report_Real-Time_AI-Powered_IDS.pdf).

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

---

## 📜 License

This project is licensed under the MIT License.
