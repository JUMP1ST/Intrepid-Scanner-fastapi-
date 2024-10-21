import tarfile
import zipfile
import os
import logging

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS = ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tar.xz', '.zip']

def extract_files(filepath: str, dest: str) -> str:
    """Extract tar or zip archives."""
    try:
        if any(filepath.endswith(ext) for ext in SUPPORTED_EXTENSIONS):
            if tarfile.is_tarfile(filepath):
                with tarfile.open(filepath, 'r:*') as tar:
                    tar.extractall(dest)
                logger.info(f"Extracted {filepath} to {dest}")
                return 'tar'
            elif zipfile.is_zipfile(filepath):
                with zipfile.ZipFile(filepath, 'r') as zip_ref:
                    zip_ref.extractall(dest)
                logger.info(f"Extracted {filepath} to {dest}")
                return 'zip'
        else:
            logger.warning(f"Unsupported file type: {filepath}")
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
    return ''

def archive_directory(src_dir: str, archive_type: str, archive_file_path: str):
    """Archive the contents of a directory based on the original archive type."""
    try:
        if archive_type == 'tar':
            with tarfile.open(archive_file_path, 'w') as tar:
                tar.add(src_dir, arcname=os.path.basename(src_dir))
            logger.info(f"Tarred directory {src_dir} to {archive_file_path}")
        elif archive_type == 'zip':
            with zipfile.ZipFile(archive_file_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for root, _, files in os.walk(src_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, start=src_dir)
                        zip_file.write(file_path, arcname)
            logger.info(f"Zipped directory {src_dir} to {archive_file_path}")
        else:
            logger.warning(f"Unsupported archive type: {archive_type}")
    except Exception as e:
        logger.error(f"Failed to archive directory {src_dir}: {e}")
