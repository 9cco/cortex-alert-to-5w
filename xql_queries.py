from datetime import datetime, timedelta
import re

# Timstamp format: Apr 11th 2023 09:15:39

# Generates the start of a XQL Query based around the timestamp.
def generateXQLQuery(timestamp, timestamp_format = "%b %d %Y %H:%M:%S", xql_time_format = "%Y-%m-%d %H:%M:%S"):

    # Format the timestamp into something readable by datetime
    # Make the timestamp have '0' in from of the day of the month.
    formatted_timestamp = re.sub(r'([A-Za-z]+) ([\d]{1}[^\d])', r'\1 0\2', timestamp)
    # Remove any 'st', 'nd' or 'th' after the day of the month.
    formatted_timestamp = re.sub(r'(\d+)[a-z]*', r'\1', formatted_timestamp)
    
    # First we make a datetime object from the timestamp
    alert_time = datetime.strptime(formatted_timestamp, timestamp_format)
    advanced_time = alert_time + timedelta(minutes=1)
    retarded_time = alert_time - timedelta(minutes=1)
    advanced_time_str = advanced_time.strftime(xql_time_format)
    retarded_time_str = retarded_time.strftime(xql_time_format)
    
    query = f'config case_sensitive = false timeframe between "{retarded_time_str}" and "{advanced_time_str}"\n'
    return query