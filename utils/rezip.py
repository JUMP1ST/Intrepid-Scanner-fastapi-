import zipfile
import os
import logging

logger = logging.getLogger(__name__)

def zip_directory(src_dir: str, zip_file_path: str):
    """Zip the contents of a directory."""
    try:
        with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for root, _, files in os.walk(src_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, start=src_dir)
                    zip_file.write(file_path, arcname)
        logger.info(f"Zipped directory {src_dir} to {zip_file_path}")
    except Exception as e:
        logger.error(f"Failed to zip directory {src_dir}: {e}")
