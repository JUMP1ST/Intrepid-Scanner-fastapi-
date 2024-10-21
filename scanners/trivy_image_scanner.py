import os
import asyncio
import logging

logger = logging.getLogger(__name__)

async def run_trivy_image_scan(image_name: str):
    """Run Trivy image scan."""
    scan_output_path = os.path.join("/app/scan-results", f"{image_name}_trivy.log")
    logger.info(f"Running Trivy image scan on: {image_name}")

    command = ["trivy", "image", image_name, "--format", "table"]

    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            with open(scan_output_path, "w") as f:
                f.write(stdout.decode())
            logger.info("Trivy image scan completed successfully.")
            return {
                "path": image_name, "scan_type": "Trivy Image", "details": stdout.decode()
            }
        else:
            logger.error(f"Trivy image scan failed: {stderr.decode()}")
            return {"error": f"Trivy image scan failed: {stderr.decode()}"}
    except Exception as e:
        logger.error(f"Exception during Trivy image scan: {e}")
        return {"error": str(e)}
