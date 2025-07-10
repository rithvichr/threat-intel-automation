# Import the IP lookup function from vt_lookup.py
from vt_lookup import vt_ip_lookup

# pandas is used to store and process the IP data
import pandas as pd

# time.sleep is used to slow down requests (API rate limit)
import time

# rich is used for nice output
from rich import print

# This function pulls a public list of suspicious IPs from Blocklist.de
def get_ip_feed(url):
    # Read the IPs from the URL into a dataframe with 1 column: "IP"
    df = pd.read_csv(url, header=None, names=["IP"])
    return df

# This function checks each IP with VirusTotal and adds threat stats
def enrich_feed(df):
    enriched = []  # List to store the enriched results

    for ip in df["IP"][:5]:  # Only process first 5 IPs to avoid hitting free API limits
        print(f"[cyan]Looking up IP:[/cyan] {ip}")  # Show which IP is being checked

        try:
            # Call the VirusTotal API to get info about the IP
            data = vt_ip_lookup(ip)

            # Safely extract the threat stats (malicious, harmless, suspicious)
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            # Store the result in a new dictionary
            enriched.append({
                "IP": ip,
                "Malicious": stats.get("malicious", 0),
                "Suspicious": stats.get("suspicious", 0),
                "Harmless": stats.get("harmless", 0)
            })

        except Exception as e:
            # If anything goes wrong, print the error
            print(f"[red]Error looking up {ip}: {e}[/red]")

        time.sleep(15)  # Wait to avoid hitting VirusTotal rate limits (important!)

    # Return a new dataframe with the enriched results
    return pd.DataFrame(enriched)

# This function filters the data to show only malicious IPs
def get_alerts(df):
    return df[df["Malicious"] > 1]  # Customize threshold if needed

# The main function ties everything together
def main():
    # Step 1: Get suspicious IPs from public threat feed
    feed_url = "https://lists.blocklist.de/lists/all.txt"
    print("[bold cyan]📥 Loading threat feed...[/bold cyan]")
    feed = get_ip_feed(feed_url)

    # Step 2: Look up each IP with VirusTotal
    print("[bold cyan]🔍 Enriching IPs using VirusTotal...[/bold cyan]")
    enriched_df = enrich_feed(feed)

    # Step 3: Show the malicious ones
    print("[bold green]✅ Done. Here are the alerts:[/bold green]")
    alerts = get_alerts(enriched_df)
    print(alerts)

if __name__ == "__main__":
    main()
