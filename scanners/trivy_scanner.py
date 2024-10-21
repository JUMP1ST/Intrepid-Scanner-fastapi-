import os
from asyncio import create_subprocess_exec, subprocess

async def run_trivy_fs_scan(path: str) -> dict:
    """Run Trivy filesystem scan."""
    output_path = "/app/scan-results/trivy_fs.log"
    command = ["trivy", "fs", path, "--format", "table"]

    process = await create_subprocess_exec(
        *command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = await process.communicate()

    if process.returncode == 0:
        with open(output_path, "w") as f:
            f.write(stdout.decode())
        return {"path": path, "scan_type": "Trivy FS", "details": stdout.decode()}
    return {"error": stderr.decode()}

async def run_trivy_image_scan(image_name: str) -> dict:
    """Run Trivy image scan."""
    output_path = f"/app/scan-results/{image_name}_trivy.log"
    command = ["trivy", "image", image_name, "--format", "table"]

    process = await create_subprocess_exec(
        *command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = await process.communicate()

    if process.returncode == 0:
        with open(output_path, "w") as f:
            f.write(stdout.decode())
        return {"path": image_name, "scan_type": "Trivy Image", "details": stdout.decode()}
    return {"error": stderr.decode()}
