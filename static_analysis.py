def basic_file_summary(data: bytes) -> dict:
    """Minimal metadata only; detailed PE parsing will be added in a later phase."""
    return {
        "file_size_bytes": len(data),
        "mz_header_present": data[:2] == b"MZ",
    }
