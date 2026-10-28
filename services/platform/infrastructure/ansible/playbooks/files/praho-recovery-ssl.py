#!/usr/bin/python3
"""Build a bounded SSL-only restore whose certificate paths belong to the target domain."""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

FEATURE_LIMIT = 4 * 1024 * 1024
CERT_FILES = {
    b"sslcertificatefile": b"ssl.combined",
    b"sslcertificatekeyfile": b"ssl.key",
    b"sslcacertificatefile": b"ssl.ca",
    b"sslcertificatechainfile": b"ssl.ca",
}
DIRECTIVE = re.compile(rb"^(\s*)(SSLCertificate(?:Key|Chain)?File|SSLCACertificateFile)\s+.*$", re.IGNORECASE)
FEATURES = ("virtualmin", "ssl", "ssl_cert", "ssl_key", "ssl_ca")


def relocate_ssl_config(content: bytes, target_id: str) -> bytes:
    if re.fullmatch(r"[0-9]{1,30}", target_id) is None:
        raise ValueError("Invalid target certificate identity")
    prefix = f"/etc/ssl/virtualmin/{target_id}/".encode()
    found: set[bytes] = set()
    lines: list[bytes] = []
    for line in content.splitlines(keepends=True):
        match = DIRECTIVE.match(line.rstrip(b"\r\n"))
        if match is None:
            lines.append(line)
            continue
        name = match[2].lower()
        found.add(name)
        # Virtualmin's native getter returns the raw directive value, including quotes.
        # This generated path contains no spaces or metacharacters and must stay unquoted.
        lines.append(match[1] + match[2] + b" " + prefix + CERT_FILES[name] + b"\n")
    if not {b"sslcertificatefile", b"sslcertificatekeyfile"}.issubset(found):
        raise ValueError("The archived SSL configuration has no complete certificate directives")
    return b"".join(lines)


def read_features(archive: Path, domain: str) -> dict[str, bytes]:
    names = {f"{domain}_{feature}": feature for feature in FEATURES}
    result: dict[str, bytes] = {}
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            path = PurePosixPath(member.name)
            feature = names.get(path.name)
            if feature is None:
                continue
            if (
                feature in result
                or not member.isfile()
                or member.size > FEATURE_LIMIT
                or path.is_absolute()
                or ".." in path.parts
            ):
                raise ValueError("Unsafe or duplicated SSL backup member")
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError("SSL backup member cannot be read")
            result[feature] = stream.read(FEATURE_LIMIT + 1)
            if len(result[feature]) > FEATURE_LIMIT:
                raise ValueError("SSL backup member exceeds the bound")
    if not {"virtualmin", "ssl", "ssl_cert"}.issubset(result):
        raise ValueError("The backup does not contain complete certificate features")
    # Native backup_ssl omits _key only when cert and key refer to the same PEM file.
    # The native restore uses separate target-owned paths; OpenSSL verifies this bundle
    # actually contains the matching private key before either derivative is restored.
    result.setdefault("ssl_key", result["ssl_cert"])
    return result


def verify_pair(features: dict[str, bytes], directory: Path) -> None:
    cert, key = directory / "cert.pem", directory / "key.pem"
    cert.write_bytes(features["ssl_cert"])
    key.write_bytes(features["ssl_key"])
    cert.chmod(0o600)
    key.chmod(0o600)
    certificate = subprocess.run(  # noqa: S603  # Fixed program and separate trusted file arguments
        ["/usr/bin/openssl", "x509", "-in", str(cert), "-pubkey", "-noout"],
        capture_output=True,
        check=True,
        timeout=30,
    ).stdout
    private = subprocess.run(  # noqa: S603  # Captured public-key output; private material stays in root-only files
        ["/usr/bin/openssl", "pkey", "-in", str(key), "-pubout"],
        capture_output=True,
        check=True,
        timeout=30,
    ).stdout
    if certificate != private:
        raise ValueError("The archived certificate does not match its private key")


def prepare(source: Path, destination: Path, domain: str, target_id: str, checksum: str) -> None:
    target = Path("/etc/ssl/virtualmin") / target_id
    info = target.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("The target certificate directory is not owned safely by this node")
    if source.is_symlink() or not source.is_file():
        raise ValueError("The source archive is not regular")
    with source.open("rb") as incoming:
        if hashlib.file_digest(incoming, "sha256").hexdigest() != checksum:
            raise ValueError("The original archive checksum changed")
    features = read_features(source, domain)
    features["ssl"] = relocate_ssl_config(features["ssl"], target_id)
    if destination.exists() and (destination.is_symlink() or not destination.is_file()):
        raise ValueError("The derived archive destination is unsafe")
    with tempfile.TemporaryDirectory(prefix=".recovery-ssl-", dir=destination.parent) as scratch:
        directory = Path(scratch)
        verify_pair(features, directory)
        output = directory / "ssl.tar.gz"
        with output.open("xb") as handle:
            output.chmod(0o600)
            with tarfile.open(fileobj=handle, mode="w:gz") as bundle:
                for feature, content in features.items():
                    member = tarfile.TarInfo(f"./{domain}_{feature}")
                    member.mode, member.size = 0o600, len(content)
                    bundle.addfile(member, io.BytesIO(content))
        os.replace(output, destination)


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("source", "destination", "domain", "domain-id", "sha256"):
        parser.add_argument(f"--{name}", required=True)
    arguments = parser.parse_args()
    if os.geteuid() != 0 or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", arguments.domain) is None:
        raise ValueError("SSL recovery requires root and a valid domain")
    if (
        re.fullmatch(r"[0-9]{1,30}", arguments.domain_id) is None
        or re.fullmatch(r"[0-9a-f]{64}", arguments.sha256) is None
    ):
        raise ValueError("Invalid SSL recovery identity")
    prepare(
        Path(arguments.source), Path(arguments.destination), arguments.domain, arguments.domain_id, arguments.sha256
    )


if __name__ == "__main__":
    main()
