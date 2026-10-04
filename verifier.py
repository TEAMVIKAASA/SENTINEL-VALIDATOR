import time
import os
import config

def get_log_checkpoint(log_path):
    """Returns the current end of file offset so we only check new logs."""
    if os.path.exists(log_path):
        return os.path.getsize(log_path)
    return 0

def verify_file_alert(log_path, expected_signature, start_offset=0, wait_seconds=config.COOLDOWN_DELAY):
    """
    Checks if a target alert signature was appended to Sentinel's local log file
    strictly after start_offset was captured.
    """
    time.sleep(wait_seconds)
    
    if not os.path.exists(log_path):
        return False, f"Log file not found at: {log_path}"
    
    try:
        with open(log_path, "rb") as f:
            f.seek(start_offset)
            raw_bytes = f.read()

        if b"\x00" in raw_bytes:
            new_content = raw_bytes.decode("utf-16", errors="ignore").lower()
        else:
            new_content = raw_bytes.decode("utf-8", errors="ignore").lower()

        if expected_signature.lower() in new_content:
            return True, "Alert captured in local log"
        
        return False, f"Signature '{expected_signature}' not observed post-dispatch"
    except Exception as e:
        return False, f"Read error: {str(e)}"