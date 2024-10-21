import os
import asyncio
import logging

logger = logging.getLogger(__name__)

async def run_trivy_repo_scan(repo_url: str):
    """Run Trivy remote repository scan."""
    scan_output_path = os.path.join("/app/scan-results", "trivy_remote_repo_scan.log")
    logger.info(f"Running Trivy remote repo scan on: {repo_url}")

    command = ["trivy", "repo", repo_url, "--format", "table"]

    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            with open(scan_output_path, "w") as f:
                f.write(stdout.decode())
            logger.info("Trivy remote repo scan completed successfully.")
            return {
                "path": repo_url, "scan_type": "Trivy Remote Repo", "details": stdout.decode()
            }
        else:
            logger.error(f"Trivy remote repo scan failed: {stderr.decode()}")
            return {"error": f"Trivy scan failed: {stderr.decode()}"}
    except Exception as e:
        logger.error(f"Exception during Trivy repo scan: {e}")
        return {"error": str(e)}
