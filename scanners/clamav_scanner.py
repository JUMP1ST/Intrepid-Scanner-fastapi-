import clamd
import logging

logger = logging.getLogger(__name__)

async def run_clamav_fs_scan(file_path: str) -> dict:
    """Run ClamAV filesystem scan."""
    try:
        cd = clamd.ClamdUnixSocket()
        scan_result = cd.multiscan(file_path)
        infected = sum(1 for result in scan_result.values() if result[0] == "FOUND")
        return {
            "path": file_path,
            "scan_type": "ClamAV FS",
            "infected": infected,
            "details": str(scan_result),
        }
    except Exception as e:
        logger.error(f"ClamAV scan failed: {e}")
        return {"error": str(e)}
