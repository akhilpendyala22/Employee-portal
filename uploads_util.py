"""
Secure file upload utilities.

Mitigates A04:2021 - Insecure Design and file upload vulnerabilities:

1. Extension allowlist (denylist would be bypassable).
2. MIME type verified by content sniffing (libmagic), not Content-Type
   header — the header is attacker-controlled.
3. Size limit enforced both at WSGI layer (MAX_CONTENT_LENGTH) and here.
4. Filenames are completely replaced with a random UUID — original
   filename is stored only as metadata. Prevents path traversal,
   double-extension tricks (shell.php.jpg), and Windows reserved names.
5. Files are stored outside the web root; served via authenticated
   download route that uses send_file with the stored UUID name.
6. SHA-256 computed for integrity / dedupe / forensic reference.
"""
import hashlib
import uuid
from pathlib import Path

import magic
from werkzeug.utils import secure_filename


class UploadError(Exception):
    pass


def _extension_of(filename: str) -> str:
    return Path(secure_filename(filename)).suffix.lower().lstrip(".")


def validate_and_store(file_storage, upload_dir: Path, allowed_ext: set,
                       allowed_mime: set, max_bytes: int) -> dict:
    """
    Validate an uploaded file and persist it under a UUID filename.

    Returns a metadata dict; raises UploadError on any policy violation.
    """
    if not file_storage or not file_storage.filename:
        raise UploadError("No file provided.")

    original = file_storage.filename
    ext = _extension_of(original)
    if ext not in allowed_ext:
        raise UploadError(f"Extension .{ext} is not permitted.")

    # Read all bytes once. MAX_CONTENT_LENGTH already capped the body at
    # the WSGI layer, but we re-check here as defense in depth.
    data = file_storage.read()
    if len(data) == 0:
        raise UploadError("Empty file.")
    if len(data) > max_bytes:
        raise UploadError("File exceeds size limit.")

    # Content sniff via libmagic — attacker cannot fake this with headers.
    detected_mime = magic.from_buffer(data, mime=True)
    if detected_mime not in allowed_mime:
        raise UploadError(
            f"File content type {detected_mime!r} is not permitted."
        )

    # Cross-check extension matches detected MIME (defeats shell.php.jpg).
    if not _extension_matches_mime(ext, detected_mime):
        raise UploadError("File extension does not match its content.")

    sha256 = hashlib.sha256(data).hexdigest()
    stored_name = f"{uuid.uuid4().hex}.{ext}"

    upload_dir.mkdir(parents=True, exist_ok=True)
    target = upload_dir / stored_name

    # Write with restrictive permissions; never executable.
    target.write_bytes(data)
    target.chmod(0o640)

    return {
        "original_filename": secure_filename(original)[:255],
        "stored_filename": stored_name,
        "mime_type": detected_mime,
        "file_size": len(data),
        "sha256": sha256,
    }


_EXT_MIME_MAP = {
    "pdf": {"application/pdf"},
    "png": {"image/png"},
    "jpg": {"image/jpeg"},
    "jpeg": {"image/jpeg"},
    "docx": {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        # python-magic on some systems reports docx as zip; allow it but
        # only when extension is docx and we've already checked allowed_mime.
        "application/zip",
    },
    "txt": {"text/plain"},
}


def _extension_matches_mime(ext: str, mime: str) -> bool:
    allowed = _EXT_MIME_MAP.get(ext, set())
    return mime in allowed
