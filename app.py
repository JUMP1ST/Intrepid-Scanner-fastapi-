import os
import shutil
import logging
from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from starlette.staticfiles import StaticFiles

from scanners.trivy_fs_scanner import run_trivy_fs_scan
from scanners.trivy_image_scanner import run_trivy_image_scan
from scanners.trivy_repo_scanner import run_trivy_repo_scan
from scanners.clone_and_local_scan import clone_and_scan_repo
from scanners.clamav_scanner import run_clamav_fs_scan
from scanners.grype_scanner import run_grype_image_scan
from scanners.syft_scanner import run_syft_sbom_scan
from scanners.yara_scanner import run_yara_scan
from utils.extract import extract_files
from utils.rezip import zip_directory

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Configuration Directories ---
UPLOAD_FOLDER = "/app/uploads"
SCAN_RESULTS_FOLDER = "/app/scan-results"
YARA_RULES_FOLDER = "/app/yara_rules"
CLAMAV_SOCKET_DIR = "/var/run/clamav"

def ensure_directories():
    """Ensure all necessary directories exist."""
    try:
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(SCAN_RESULTS_FOLDER, exist_ok=True)
        os.makedirs(YARA_RULES_FOLDER, exist_ok=True)
        os.makedirs(CLAMAV_SOCKET_DIR, exist_ok=True)
        logger.info("All directories are created successfully.")
    except Exception as e:
        logger.error(f"Failed to create directories: {e}")
        raise

# Ensure directories are created on startup
ensure_directories()

# --- FastAPI Application Setup ---
app = FastAPI()

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def get_index(request: Request):
    """Serve the index.html."""
    return templates.TemplateResponse("index.html", {"request": request, "scan_results": []})

@app.post("/scan/", response_class=HTMLResponse)
async def scan_file(
    request: Request,
    scan_type: str = Form(...),
    file: UploadFile = File(None),
    image_name: str = Form(None),
    repo_url: str = Form(None),
):
    """Handle filesystem, image, and repository scans."""
    scan_results = []

    if scan_type == "filesystem" and file:
        # Filesystem Scan
        file_path = os.path.join(UPLOAD_FOLDER, file.filename)
        with open(file_path, "wb") as f:
            f.write(await file.read())

        extract_path = os.path.join(UPLOAD_FOLDER, "extracted")
        os.makedirs(extract_path, exist_ok=True)

        if extract_files(file_path, extract_path):
            scan_results.extend([
                await run_trivy_fs_scan(extract_path),
                await run_clamav_fs_scan(extract_path),
                await run_yara_scan(extract_path),
            ])
            # Zip scanned files
            zip_file_path = os.path.join(UPLOAD_FOLDER, f"{file.filename}_scanned.zip")
            zip_directory(extract_path, zip_file_path)
            scan_results.append({
                "path": zip_file_path,
                "scan_type": "Re-zipped Archive",
                "details": "Files re-zipped after scanning."
            })
            shutil.rmtree(extract_path)  # Cleanup
        os.remove(file_path)

    elif scan_type == "image" and image_name:
        # Image Scan
        scan_results.extend([
            await run_trivy_image_scan(image_name),
            await run_grype_image_scan(image_name),
            await run_syft_sbom_scan(image_name),
        ])

    elif scan_type == "repo" and repo_url:
        # Repository Scan
        repo_scan_results = await clone_and_scan_repo(repo_url)
        for result in repo_scan_results:
            scan_results.append(result)

    else:
        raise HTTPException(status_code=400, detail="Invalid scan type or missing parameters.")

    return templates.TemplateResponse("scan.html", {"request": request, "scan_results": scan_results})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

