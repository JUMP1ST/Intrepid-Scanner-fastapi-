import os
import shutil
import logging
import git
from scanners.trivy_fs_scanner import run_trivy_fs_scan
from scanners.trivy_repo_scanner import run_trivy_repo_scan
from scanners.clamav_scanner import run_clamav_fs_scan

logger = logging.getLogger(__name__)

async def clone_and_scan_repo(repo_url: str):
    """Clone a Git repository locally and perform multiple scans."""
    repo_name = os.path.basename(repo_url).replace(".git", "")
    repo_path = os.path.join("/app/uploads", repo_name)

    results = []

    # Step 1: Run Trivy remote repo scan
    logger.info(f"Running remote Trivy repo scan on: {repo_url}")
    results.append(await run_trivy_repo_scan(repo_url))

    # Step 2: Clone the repository
    if os.path.exists(repo_path):
        shutil.rmtree(repo_path)

    try:
        logger.info(f"Cloning repository from {repo_url} to {repo_path}")
        git.Repo.clone_from(repo_url, repo_path)
        logger.info(f"Successfully cloned repository: {repo_path}")
    except Exception as e:
        logger.error(f"Failed to clone repository: {e}")
        return [{"error": f"Failed to clone repository: {e}"}]

    # Step 3: Run local Trivy repo scan, Trivy FS scan, and ClamAV FS scan
    try:
        results.extend([
            await run_trivy_repo_scan(repo_path),   # Trivy local repo scan
            await run_trivy_fs_scan(repo_path),     # Trivy FS scan
            await run_clamav_fs_scan(repo_path),    # ClamAV FS scan
        ])
    except Exception as e:
        logger.error(f"Error during local scans: {e}")
        results.append({"error": f"Error during local scans: {e}"})

    # Step 4: Cleanup cloned repository
    shutil.rmtree(repo_path)
    logger.info(f"Cleaned up cloned repository: {repo_path}")

    return results
