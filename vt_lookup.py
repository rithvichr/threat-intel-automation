# vt_lookup.py

# Import the requests library to make HTTP requests
import requests

# Import the API key from your config file
from config import VT_API_KEY

# Define a function to look up IP addresses on VirusTotal
def vt_ip_lookup(ip):
    # Build the API URL using the IP address
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    
    # Set the API key in the request headers
    headers = {"x-apikey": VT_API_KEY}
    
    # Send a GET request to the VirusTotal API
    response = requests.get(url, headers=headers)
    
    # Return the JSON response from the API
    return response.json()
