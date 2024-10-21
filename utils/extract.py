import tarfile
import zipfile
import os
import logging

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS = ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tar.xz', '.zip']

def extract_files(filepath: str, dest: str) -> bool:
    """Extract tar or zip archives."""
    try:
        if any(filepath.endswith(ext) for ext in SUPPORTED_EXTENSIONS):
            if tarfile.is_tarfile(filepath):
                with tarfile.open(filepath, 'r:*') as tar:
                    tar.extractall(dest)
                logger.info(f"Extracted {filepath} to {dest}")
                return True
            elif zipfile.is_zipfile(filepath):
                with zipfile.ZipFile(filepath, 'r') as zip_ref:
                    zip_ref.extractall(dest)
                logger.info(f"Extracted {filepath} to {dest}")
                return True
        else:
            logger.warning(f"Unsupported file type: {filepath}")
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
    return False
