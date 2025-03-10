# Description: This script reads the JSON file containing the VirusTotal report and inserts the data into a MariaDB database.
# The script first loads the JSON file, extracts the data, and then connects to the MariaDB database.
# It creates a table to store the VirusTotal report if it doesn't exist and prepares an INSERT query.
# The script then inserts the data into the database using the INSERT query and ON DUPLICATE KEY UPDATE to handle duplicate records.
# Finally, the script closes the database connection.
# Note: Make sure to replace the environment variables with your own values.


# Import necessary libraries
import json
import mariadb
import sys
import os

# Load the JSON file
with open('virustotal_response.json', 'r', encoding='utf-8') as f:
    vt_data = json.load(f)

# Extract the data from the JSON
data = vt_data.get("data", {}) 
domain = data.get("id")  # e.g., "google.com"
domain_type = data.get("type")
link_self = data.get("links", {}).get("self")
# Extract attributes if available
attributes = data.get("attributes", {})
reputation = attributes.get("reputation")
last_dns_records_date = attributes.get("last_dns_records_date")
last_https_certificate_date = attributes.get("last_https_certificate_date")
last_analysis_date = attributes.get("last_analysis_date")

# Extract analysis stats if available
analysis_stats = attributes.get("last_analysis_stats", {})
malicious = analysis_stats.get("malicious")
suspicious = analysis_stats.get("suspicious")
undetected = analysis_stats.get("undetected")
harmless = analysis_stats.get("harmless")

# For this part, you need to replace the environment variables with your own values or hardcode them
# Connect to your MariaDB database
try:
    conn = mariadb.connect(
        user= os.getenv("USER_MARIADB"), 
        password=os.getenv("PASSWORD_MARIADB"),
        host=os.getenv("HOST_MARIADB"),
        port=os.getenv("PORT_MARIADB"),
        database=os.getenv("DATABASE_MARIADB")
    )
except mariadb.Error as e:
    print(f"Error connecting to MariaDB: {e}")
    sys.exit(1)

cursor = conn.cursor()

# Create a table to store the VirusTotal report if it doesn't exist
create_table_query = """
CREATE TABLE IF NOT EXISTS virustotal_reports (
    domain VARCHAR(255) PRIMARY KEY,
    domain_type VARCHAR(50),
    link_self TEXT,
    reputation INT,
    last_dns_records_date INT,
    last_https_certificate_date INT,
    last_analysis_date INT,
    malicious INT,
    suspicious INT,
    undetected INT,
    harmless INT
);
"""
cursor.execute(create_table_query)

# Prepare an INSERT query; using ON DUPLICATE KEY UPDATE in case the record already exists
insert_query = """
INSERT INTO virustotal_reports (
    domain, domain_type, link_self, reputation, last_dns_records_date, 
    last_https_certificate_date, last_analysis_date, malicious, suspicious, undetected, harmless
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    domain_type = VALUES(domain_type),
    link_self = VALUES(link_self),
    reputation = VALUES(reputation),
    last_dns_records_date = VALUES(last_dns_records_date),
    last_https_certificate_date = VALUES(last_https_certificate_date),
    last_analysis_date = VALUES(last_analysis_date),
    malicious = VALUES(malicious),
    suspicious = VALUES(suspicious),
    undetected = VALUES(undetected),
    harmless = VALUES(harmless);
"""

data_tuple = (
    domain, domain_type, link_self, reputation, last_dns_records_date,
    last_https_certificate_date, last_analysis_date, malicious, suspicious, undetected, harmless
)

# Insert the data
try:
    cursor.execute(insert_query, data_tuple)
    conn.commit()
    print("Data inserted successfully!")
except mariadb.Error as e:
    print(f"Error inserting data: {e}")
    conn.rollback()

conn.close()
