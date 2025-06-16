import win32evtlog
import pandas as pd
import sqlite3
import re
import datetime
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

def get_windows_logs(server="localhost", log_type="System"):
    # Retrieves Windows Event Logs from the specified log type (System, Application, Security).

    log_handle = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    logs = []

    # Get current time and calculate 7-day threshold
    seven_days_ago = datetime.datetime.now() - datetime.timedelta(days=7)

    while True:
        events = win32evtlog.ReadEventLog(log_handle, flags, 0)
        if not events:
            break

        for event in events:
            event_time = event.TimeGenerated
            if event_time >= seven_days_ago: # Filter logs only from last 7 days
                logs.append({
                    "TimeGenerated": event.TimeGenerated.Format(),
                    "EventID": event.EventID,
                    "EventType": event.EventType,
                    "Source": event.SourceName,
                    "Message": " ".join(event.StringInserts) if event.StringInserts else "No message available"
                })
    win32evtlog.CloseEventLog(log_handle)
    return pd.DataFrame(logs) # Return filtered logs


# Get logs
df_logs = get_windows_logs(log_type="Application")

# Convert timestamp to datetime for time-based analysis
df_logs["TimeGenerated"] = pd.to_datetime(df_logs["TimeGenerated"])

# Extract User/IP from message (assuming logs contain identifiable use/IP data)
df_logs["User_IP"] = df_logs["Message"].apply(
    lambda x: re.search(r"User: (\S+)|IP: (\S+)", str(x))
)
df_logs["User_IP"] = df_logs["User_IP"].apply(lambda match: match.group(1) if match else None)


# Time-based detection
df_logs["TimeDiff"] = df_logs.groupby("User_IP")["TimeGenerated"].diff().dt.total_seconds() 


# Multiple suspicious events patterns
suspicious_patterns = {
    "Failed Login": r"(?i)failed login|invalid credentials|logon failure",
    "Privilege Escalation": r"(?i)privilege escalation|elevated privileges|admin access",
    "Unauthorized Access": r"(?i)unauthorized access|access denied|permission denied",
    "Critical Error": r"(?i)critical error|system failure|blue screen",
    "Possible Malware": r"(?i)malware detected|virus found|suspicious activity|ransomware",
    "Access Denied": r"(?i)access denied|permission denied|not authorized",
}

def detect_suspicious_events(df):
    df["Suspicious Event"] = None # Initialize column

    for event_type, pattern in suspicious_patterns.items():
        df.loc[df["Message"].str.contains(pattern, na=False), "Suspicious Event"] = event_type

    return df[df["Suspicious Event"].notna()] # Return only suspicious events

# Apply detection to the logs
suspicious_logs = detect_suspicious_events(df_logs)
print (suspicious_logs)

# Flag consecutive failed login attempts within a suspicious window (e.g. 10 minutes)
df_logs["Rapid-Fire Logins"] = (df_logs["Suspicious Event"] == "Failed Login") & (df_logs["TimeDiff"] <= 600)

# Identify repeated offenders

df_logs["Persistent Attackers"] = df_logs.groupby("User_IP")["Rapid-Fire Logins"].transform("sum") > 5

# Group by time (e.g. by hour) window and calculate frequency metrics
df_logs["Failed Login Frequency"] = df_logs.groupby([df_logs["User_IP"], df_logs["TimeGenerated"].dt.hour])["Suspicious Event"].transform(lambda x: (x == "Failed Login").sum())

# Flag excessive failed login attempts
df_logs["Brute Force Indicator"] = df_logs["Failed Login Frequency"] >= 5 # Adjust threshold 

# Define brute-force detection criteria (e.g., multiple failed attempts within a short time frame)
df_logs["Failed Login Count"] = df_logs.groupby("Source")["Suspicious Event"].transform(lambda x: (x == "Failed Login").sum())

# Flag repeated failed login attempts
df_logs["Brute Force Attack"] = df_logs["Failed Login Count"] >= 5 # Adjust Threshold


class EventStateMachine:
    def __init__(self):
        self.state = "NORMAL"
        self.previous_event = None
    
    def transition(self, event):
        """Determines state transitions based on detected suspicious events."""
        event_type = event.get("Suspicious Event", "NORMAL")

        if event_type == "Failed Login":
            self.state = "FAILED_LOGIN"
        
        elif event_type == "Privilege Escalation" and self.state == "FAILED_LOGIN":
            self.state = "ESCALATION_ALERT"
            print(f"⚠️ ALERT: Suspicious Privilege escalation detected! EventID: {event['EventID']}")

        elif event_type in suspicious_patterns.keys():
            print(f"⚠️ ALERT: {event_type} detected! EventID: {event['EventID']}")

        self.previous_event = event_type # Track last event for correlation

# Initialize state machine
state_machine = EventStateMachine()

# Apply state machine transition to suspicious logs
for _, event in suspicious_logs.iterrows():
    state_machine.transition(event)

# Feature Engineering - Convert categorical values & create frequency metrics
df_logs["EventID"] = df_logs["EventID"].astype(int) # Ensuring numerical representation
df_logs["Message Length"] = df_logs["Message"].apply(lambda x: len(str(x)))
df_logs["Event_Frequency"] = df_logs.groupby("EventID")["EventID"].transform("count")
df_logs["Time_Difference"] = df_logs["TimeGenerated"].diff().dt.total_seconds()

# Fit the model
for contamination_level in [0.005, 0.01, 0.02, 0.05]:
    model = IsolationForest(contamination=contamination_level, random_state=42)
    df_logs["Anomaly Score"] = model.fit_predict(df_logs[["EventID", "Message Length"]]) # -1 indicates anomaly
    print(f"Anomalies at contamination {contamination_level}:")
    print(df_logs[df_logs["Anomaly Score"] == -1])


# Normalize features before clustering

features = df_logs[df_logs["Anomaly Score"] != -1][["EventID", "Message Length"]] # Remove Isolation Forest anomalies
scaled_features = StandardScaler().fit_transform(features)

# Apply DBSCAN clustering

dbscan = DBSCAN(eps=0.5, min_samples=10).fit(scaled_features)
df_logs.loc[df_logs["Anomaly Score"] != -1, "DBSCAN Cluster"] = dbscan.labels_ # Assign clusters

# Investigate DBSCAN outliers (-1 means anomaly)
print(df_logs[df_logs["DBSCAN Cluster"] == -1])

# Group all suspicious events by hour

suspicious_events_by_hour = df_logs[df_logs["Suspicious Event"].notna()].groupby(
    [df_logs["TimeGenerated"].dt.hour, df_logs["Suspicious Event"]]
).size().unstack() # Pivot for easier plotting

# Plot multiple suspicious events over time

plt.figure(figsize=(12, 6))

# Iterate over all event categories and plot each

for event_type in suspicious_events_by_hour.columns:
    plt.plot(suspicious_events_by_hour.index, suspicious_events_by_hour[event_type], marker='o', linestyle='-', label=event_type)

plt.xlabel("Hour of the Day")
plt.ylabel("Number of Events")
plt.title("Suspicious Events Over Time")
plt.legend()
plt.grid()
plt.show()


def store_logs_in_sqlite(df, db_name="windows_logs.db"):
    conn = sqlite3.connect(db_name)

    # Store all logs
    df.to_sql("event_logs", conn, if_exists="replace", index=False)

    # Store only flagged anomalies
    flagged_df = df[df["Suspicious Event"].notna() | df["Brute Force Indicator"] | (df["Anomaly Score"] == -1)]
    flagged_df.to_sql("flagged_events", conn, if_exists="replace", index=False)
    
    conn.commit()
    conn.close()
    print("Logs saved successfully. Flagged events stored separately for auditing.")

# Storing logs

store_logs_in_sqlite(df_logs)
print("Logs saved successfully to SQLite!")



