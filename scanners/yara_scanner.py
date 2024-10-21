import os
import yara
import logging

logger = logging.getLogger(__name__)

async def run_yara_scan(target_path: str) -> dict:
    """Run YARA scan."""
    try:
        rules = yara.compile(filepath="/app/yara_rules/malware.yar")
        matches = []

        for root, _, files in os.walk(target_path):
            for file in files:
                file_path = os.path.join(root, file)
                match = rules.match(file_path)
                if match:
                    matches.append({"path": file_path, "matches": str(match)})

        return matches if matches else {"status": "No matches found"}
    except Exception as e:
        logger.error(f"YARA scan failed: {e}")
        return {"error": str(e)}
