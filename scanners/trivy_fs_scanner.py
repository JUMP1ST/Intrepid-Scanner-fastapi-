import os
import asyncio
import logging

logger = logging.getLogger(__name__)

async def run_trivy_fs_scan(path: str):
    """Run Trivy filesystem scan."""
    scan_output_path = os.path.join("/app/scan-results", "trivy_fs.log")
    logger.info(f"Running Trivy filesystem scan on: {path}")

    command = ["trivy", "fs", path, "--format", "table"]

    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            with open(scan_output_path, "w") as f:
                f.write(stdout.decode())
            logger.info("Trivy filesystem scan completed successfully.")
            return {
                "path": path, "scan_type": "Trivy FS", "details": stdout.decode()
            }
        else:
            logger.error(f"Trivy filesystem scan failed: {stderr.decode()}")
            return {"error": f"Trivy scan failed: {stderr.decode()}"}
    except Exception as e:
        logger.error(f"Exception during Trivy scan: {e}")
        return {"error": str(e)}
