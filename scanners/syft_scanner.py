import os
from asyncio import create_subprocess_exec, subprocess

async def run_syft_sbom_scan(image_name: str) -> dict:
    """Generate SBOM using Syft."""
    output_path = f"/app/scan-results/{image_name}_syft.log"
    command = ["syft", image_name, "-o", "table"]

    process = await create_subprocess_exec(
        *command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = await process.communicate()

    if process.returncode == 0:
        with open(output_path, "w") as f:
            f.write(stdout.decode())
        return {"path": image_name, "scan_type": "Syft SBOM", "details": stdout.decode()}
    return {"error": stderr.decode()}
