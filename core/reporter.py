def log_change(change):
    with open("logs/registry_changes.log", "a") as f:
        f.write(f"{change}\n")

def alert(change):
    with open("logs/alerts.log", "a") as f:
        f.write(f"ALERT: {change}\n")
