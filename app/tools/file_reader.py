"""
File Reader Tool with Path Traversal Vulnerability & Canonicalization Defense.
"""
from pathlib import Path
from typing import Dict, Any
from app.config import ALLOWED_DOCS_DIR, SANDBOX_FS_DIR

class FileReaderTool:
    name = "read_file"
    description = "Read the text contents of a document from the company's allowed document directory."

    @staticmethod
    def execute(filepath: str, mitigated: bool = False) -> Dict[str, Any]:
        """
        Executes file reading.
        If mitigated is False, path traversal vulnerability exists.
        If mitigated is True, strict sandbox containment and extension checks are enforced.
        """
        try:
            if not mitigated:
                # VULNERABLE: Direct path concatenation allows directory traversal (../ or ../../)
                target_path = (ALLOWED_DOCS_DIR / filepath).resolve()
                if not target_path.exists():
                    # Check sandbox fs root traversal
                    clean_rel = filepath.replace("../", "").replace("..\\", "").lstrip("/\\")
                    alt_path = (SANDBOX_FS_DIR / clean_rel).resolve()
                    if alt_path.exists():
                        target_path = alt_path

                if not target_path.exists():
                    return {"status": "error", "message": f"File not found: {filepath}"}
                
                content = target_path.read_text(encoding="utf-8")
                return {
                    "status": "success",
                    "filepath": str(target_path),
                    "content": content
                }
            else:
                # MITIGATED: Canonical path checking & sandbox boundary enforcement
                safe_base = ALLOWED_DOCS_DIR.resolve()
                target_path = (safe_base / filepath).resolve()

                # Boundary containment check
                if not target_path.is_relative_to(safe_base):
                    return {
                        "status": "blocked",
                        "error_type": "PathTraversalBlocked",
                        "message": f"SECURITY VIOLATION: Path traversal detected. Access outside {safe_base.name} is prohibited."
                    }

                # Extension whitelist
                allowed_extensions = {".txt", ".md", ".json", ".log"}
                if target_path.suffix.lower() not in allowed_extensions:
                    return {
                        "status": "blocked",
                        "error_type": "IllegalFileExtension",
                        "message": f"SECURITY VIOLATION: File extension {target_path.suffix} is not in allowed whitelist."
                    }

                if not target_path.exists():
                    return {"status": "error", "message": f"File not found in sandbox: {filepath}"}

                content = target_path.read_text(encoding="utf-8")
                return {
                    "status": "success",
                    "filepath": str(target_path.relative_to(safe_base)),
                    "content": content
                }

        except Exception as e:
            return {"status": "error", "message": f"File read error: {str(e)}"}
