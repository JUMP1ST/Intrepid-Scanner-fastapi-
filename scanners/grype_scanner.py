import os
from asyncio import create_subprocess_exec, subprocess

async def run_grype_image_scan(image_name: str) -> dict:
    """Run Grype image scan."""
    output_path = f"/app/scan-results/{image_name}_grype.log"
    command = ["grype", image_name, "--output", "table"]

    process = await create_subprocess_exec(
        *command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = await process.communicate()

    if process.returncode == 0:
        with open(output_path, "w") as f:
            f.write(stdout.decode())
        return {"path": image_name, "scan_type": "Grype Image", "details": stdout.decode()}
    return {"error": stderr.decode()}
