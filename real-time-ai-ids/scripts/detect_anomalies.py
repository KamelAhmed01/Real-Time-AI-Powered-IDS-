import time
import pandas as pd
import joblib
from elasticsearch import Elasticsearch, exceptions as es_exceptions
from datetime import datetime, timedelta
import os

# Define file paths relative to the script location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE = os.path.join(SCRIPT_DIR, 'ids_model.pkl')

# Elasticsearch connection details (use environment variables or defaults)
ES_HOST = os.getenv("ES_HOST", "elasticsearch")
ES_PORT = int(os.getenv("ES_PORT", "9200"))
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASSWORD = os.getenv("ES_PASSWORD", "changeme")
ES_SCHEME = os.getenv("ES_SCHEME", "http")

# Anomaly score threshold (can be tuned)
ANOMALY_THRESHOLD = -0.3 # As per original script, might need tuning based on model and data

print(f"Connecting to Elasticsearch at {ES_SCHEME}://{ES_HOST}:{ES_PORT}")

# Retry connection to Elasticsearch
retries = 10
retry_delay = 30 # seconds
for i in range(retries):
    try:
        es = Elasticsearch(
            [{'host': ES_HOST, 'port': ES_PORT, 'scheme': ES_SCHEME}],
            basic_auth=(ES_USER, ES_PASSWORD)
        )
        if es.ping():
            print("Successfully connected to Elasticsearch.")
            break
        else:
            print("Connected to Elasticsearch, but ping failed. Retrying...")
    except es_exceptions.ConnectionError as e:
        print(f"Elasticsearch connection failed (attempt {i+1}/{retries}): {e}. Retrying in {retry_delay}s...")
    time.sleep(retry_delay)
else:
    print("Failed to connect to Elasticsearch after several retries. Exiting.")
    exit(1)

print(f"Loading model from {MODEL_FILE}...")
if not os.path.exists(MODEL_FILE):
    print(f"Error: Model file {MODEL_FILE} not found. Please train the model first. Exiting.")
    exit(1)
model = joblib.load(MODEL_FILE)
print("Model loaded successfully.")

features = ['duration', 'pkts_toserver', 'pkts_toclient', 'bytes_toserver', 'bytes_toclient']
last_run_timestamp = datetime.now() - timedelta(minutes=5) # Look back 5 minutes initially

print("Starting real-time anomaly detection loop...")
while True:
    try:
        current_timestamp = datetime.now()
        query_body = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"event.type": "flow"}},
                        {"range": {"@timestamp": {"gte": last_run_timestamp.isoformat(), "lt": current_timestamp.isoformat()}}}
                    ]
                }
            },
            "size": 10000 # Process up to 10000 flows per interval
        }

        # print(f"Querying Elasticsearch for flows between {last_run_timestamp.isoformat()} and {current_timestamp.isoformat()}")
        res = es.search(index="filebeat-*", body=query_body)
        
        raw_flows = res['hits']['hits']
        # print(f"Retrieved {len(raw_flows)} raw flow events from Elasticsearch.")

        if raw_flows:
            processed_flows = []
            for hit in raw_flows:
                flow_data = hit['_source'].get('flow', {})
                source_data = hit['_source'].get('source', {})
                destination_data = hit['_source'].get('destination', {})
                event_data = hit['_source'].get('event', {})

                try:
                    start_time_str = flow_data.get('start')
                    end_time_str = flow_data.get('end')
                    
                    if not start_time_str or not end_time_str:
                        # print(f"Skipping flow due to missing start/end time: {flow_data.get('id', 'N/A')}")
                        continue

                    # Handle different timestamp formats (with or without milliseconds)
                    try:
                        start_time = pd.to_datetime(start_time_str)
                    except ValueError:
                        start_time = pd.to_datetime(start_time_str.split('.')[0]) # Try without millis
                    
                    try:
                        end_time = pd.to_datetime(end_time_str)
                    except ValueError:
                        end_time = pd.to_datetime(end_time_str.split('.')[0]) # Try without millis

                    duration = (end_time - start_time).total_seconds()
                    if duration < 0: duration = 0 # Ensure duration is not negative

                    flow_record = {
                        'timestamp': hit['_source'].get('@timestamp'),
                        'duration': duration,
                        'pkts_toserver': flow_data.get('pkts_toserver', 0),
                        'pkts_toclient': flow_data.get('pkts_toclient', 0),
                        'bytes_toserver': flow_data.get('bytes_toserver', 0),
                        'bytes_toclient': flow_data.get('bytes_toclient', 0),
                        'flow_id': flow_data.get('id', ''),
                        'app_proto': flow_data.get('app_proto', 'unknown'),
                        'src_ip': source_data.get('ip', ''),
                        'src_port': source_data.get('port', 0),
                        'dest_ip': destination_data.get('ip', ''),
                        'dest_port': destination_data.get('port', 0),
                        'proto': flow_data.get('proto', ''),
                        'event_type': event_data.get('type', '')
                    }
                    processed_flows.append(flow_record)
                except Exception as e:
                    print(f"Error processing individual flow: {e}. Flow data: {flow_data}")
                    continue
            
            if not processed_flows:
                # print(f"{current_timestamp}: No processable flows in the time window.")
                last_run_timestamp = current_timestamp
                time.sleep(10) # Check more frequently if no flows
                continue

            df = pd.DataFrame(processed_flows)
            # print(f"Created DataFrame with {len(df)} flows for scoring.")

            if not df.empty and all(feature in df.columns for feature in features):
                df_features = df[features].copy()
                # Ensure no NaN/inf values before prediction
                df_features.fillna(0, inplace=True) # Replace NaNs with 0 or a suitable value
                df_features.replace([float('inf'), float('-inf')], 0, inplace=True) # Replace infs

                scores = model.decision_function(df_features)
                df['anomaly_score'] = scores
                df['is_anomaly'] = scores < ANOMALY_THRESHOLD # Use defined threshold
                
                anomalies_df = df[df['is_anomaly']]
                # print(f"Scored flows. Found {len(anomalies_df)} anomalies.")

                if not anomalies_df.empty:
                    print(f"Detected {len(anomalies_df)} anomalies. Indexing to 'suricata-anomalies'...")
                    for _, row in anomalies_df.iterrows():
                        try:
                            # Convert Timestamp to ISO format string for Elasticsearch
                            if 'timestamp' in row and isinstance(row['timestamp'], pd.Timestamp):
                                row['timestamp'] = row['timestamp'].isoformat()
                            es.index(index='suricata-anomalies', document=row.to_dict())
                        except Exception as e_index:
                            print(f"Error indexing anomaly to Elasticsearch: {e_index}. Document: {row.to_dict()}")
                    print(f"Successfully indexed {len(anomalies_df)} anomalies.")
                
                print(f"{current_timestamp}: Processed {len(df)} flows. Found {len(anomalies_df)} anomalies. Anomaly threshold: {ANOMALY_THRESHOLD}")
            elif df.empty:
                print(f"{current_timestamp}: No flows to process after filtering.")
            else:
                print(f"{current_timestamp}: DataFrame is missing one or more required features for scoring. Available columns: {df.columns.tolist()}")
        else:
            print(f"{current_timestamp}: No new flow events from Elasticsearch in the last interval.")

        last_run_timestamp = current_timestamp
        time.sleep(30)  # Interval for querying Elasticsearch

    except es_exceptions.ConnectionError as e:
        print(f"Elasticsearch connection error during loop: {e}. Attempting to reconnect...")
        # Attempt to re-establish connection
        for i in range(retries):
            time.sleep(retry_delay)
            try:
                es = Elasticsearch(
                    [{'host': ES_HOST, 'port': ES_PORT, 'scheme': ES_SCHEME}],
                    basic_auth=(ES_USER, ES_PASSWORD)
                )
                if es.ping():
                    print("Reconnected to Elasticsearch.")
                    break
            except es_exceptions.ConnectionError:
                print(f"Reconnect attempt {i+1} failed.")
        else:
            print("Failed to reconnect to Elasticsearch. Exiting.")
            exit(1)
    except Exception as e:
        print(f"An unexpected error occurred in the detection loop: {e}")
        print("Continuing after 10 seconds...")
        time.sleep(10)

