import os
from dotenv import load_dotenv

load_dotenv()

# Network target endpoint (Machine / VM where Project Sentinel is listening)
TARGET_IP = os.getenv("TARGET_IP", "127.0.0.1")
TARGET_PORT = int(os.getenv("TARGET_PORT", 80))

# Packet parameters
PACKET_COUNT = int(os.getenv("PACKET_COUNT", 5))
COOLDOWN_DELAY = float(os.getenv("COOLDOWN_DELAY", 1.5))

# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
ALERTS_TABLE = os.getenv("ALERTS_TABLE", "alerts")