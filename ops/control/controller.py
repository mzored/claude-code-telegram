from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

CANONICAL_ORIGIN = "https://github.com/mzored/claude-code-telegram.git"
DEPLOY_HOST = "mybots"
REMOTE_WORKER = "/home/mzored/.local/lib/assist-ai/control/v1/ops/control/worker.py"


class ControllerError(RuntimeError):
    """The local deployment controller rejected a request or handshake."""


def _git(
    repo: Path, *arguments: str, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=check,
        text=True,
        capture_output=True,
    )


@dataclass(frozen=True)
class CheckoutIdentity:
    head: str
    status: str
    worktree_diff: str
    index_diff: str
    index_sha256: str

    @classmethod
    def capture(cls, repo: Path) -> "CheckoutIdentity":
        head = _git(repo, "rev-parse", "HEAD").stdout.strip()
        status = _git(
            repo,
            "status",
            "--porcelain=v2",
            "--untracked-files=all",
        ).stdout
        worktree_diff = _git(repo, "diff", "--binary").stdout
        index_diff = _git(repo, "diff", "--cached", "--binary").stdout
        index_text = _git(repo, "rev-parse", "--git-path", "index").stdout.strip()
        index_path = Path(index_text)
        if not index_path.is_absolute():
            index_path = repo / index_path
        index_digest = (
            hashlib.sha256(index_path.read_bytes()).hexdigest()
            if index_path.exists()
            else "missing"
        )
        return cls(
            head=head,
            status=status,
            worktree_diff=worktree_diff,
            index_diff=index_diff,
            index_sha256=index_digest,
        )


@dataclass
class Artifact:
    sha: str
    tree: str
    archive: Path
    sha256: str
    _temporary: tempfile.TemporaryDirectory[str]

    def cleanup(self) -> None:
        self._temporary.cleanup()


def validate_sha(sha: str) -> None:
    if len(sha) != 40 or any(character not in "0123456789abcdef" for character in sha):
        raise ControllerError("commit must be a full lowercase 40-character SHA")


def prepare_artifact(
    checkout: Path,
    sha: str,
    *,
    origin_url: str = CANONICAL_ORIGIN,
) -> Artifact:
    validate_sha(sha)
    checkout = checkout.resolve()
    before = CheckoutIdentity.capture(checkout)
    if before.status or before.worktree_diff or before.index_diff:
        raise ControllerError("deployment requires a clean checkout")
    configured_origin = _git(checkout, "remote", "get-url", "origin").stdout.strip()
    if configured_origin != origin_url:
        raise ControllerError(f"origin must be {origin_url}")

    temporary: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory(
        prefix="assist-ai-deploy-"
    )
    bare = Path(temporary.name) / "origin.git"
    archive = Path(temporary.name) / "candidate.tar"
    try:
        subprocess.run(["git", "init", "--bare", "--quiet", str(bare)], check=True)
        _git(bare, "remote", "add", "origin", origin_url)
        _git(
            bare,
            "fetch",
            "--quiet",
            "--no-tags",
            "origin",
            "+refs/heads/main:refs/remotes/origin/main",
        )
        if _git(
            bare,
            "merge-base",
            "--is-ancestor",
            before.head,
            "refs/remotes/origin/main",
            check=False,
        ).returncode:
            raise ControllerError(
                "control checkout contains commits not on origin/main"
            )
        if _git(bare, "cat-file", "-e", f"{sha}^{{commit}}", check=False).returncode:
            raise ControllerError("commit is not available from origin/main")
        if _git(
            bare,
            "merge-base",
            "--is-ancestor",
            sha,
            "refs/remotes/origin/main",
            check=False,
        ).returncode:
            raise ControllerError("commit is not an ancestor of origin/main")
        tree = _git(bare, "rev-parse", f"{sha}^{{tree}}").stdout.strip()
        with archive.open("wb") as handle:
            subprocess.run(
                ["git", "-C", str(bare), "archive", "--format=tar", sha],
                stdout=handle,
                check=True,
            )
        archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        after = CheckoutIdentity.capture(checkout)
        if after != before:
            raise ControllerError("deployment preparation changed the control checkout")
        return Artifact(sha, tree, archive, archive_digest, temporary)
    except Exception as error:
        if CheckoutIdentity.capture(checkout) != before:
            temporary.cleanup()
            raise ControllerError(
                "failed deployment preparation changed the control checkout"
            ) from error
        temporary.cleanup()
        raise


def deploy(
    checkout: Path,
    action: str,
    sha: str,
    ssh_binary: str = "ssh",
    *,
    origin_url: str = CANONICAL_ORIGIN,
) -> str:
    artifact = prepare_artifact(checkout, sha, origin_url=origin_url)
    before = CheckoutIdentity.capture(checkout)
    try:
        with artifact.archive.open("rb") as archive:
            result = subprocess.run(
                [
                    ssh_binary,
                    DEPLOY_HOST,
                    "/usr/bin/python3",
                    REMOTE_WORKER,
                    "receive",
                    action,
                    artifact.sha,
                    artifact.tree,
                    artifact.sha256,
                ],
                stdin=archive,
                text=False,
                capture_output=True,
            )
        output = result.stdout.decode(errors="replace")
        error = result.stderr.decode(errors="replace")
        if result.returncode:
            raise ControllerError(error.strip() or "mybots rejected the deployment")
        handshake = f"DEPLOYED_SHA={sha}"
        if handshake not in output.splitlines():
            raise ControllerError("mybots did not confirm the requested commit")
        return output
    finally:
        artifact.cleanup()
        if CheckoutIdentity.capture(checkout) != before:
            raise ControllerError("deployment changed the control checkout")


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="deploy an exact origin/main commit to mybots"
    )
    parser.add_argument("action", choices=("deploy", "rollback"))
    parser.add_argument("sha")
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help=argparse.SUPPRESS,
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv or sys.argv[1:])
    try:
        output = deploy(
            arguments.repo,
            arguments.action,
            arguments.sha,
            ssh_binary=os.environ.get("SSH_BIN", "ssh"),
        )
    except (ControllerError, OSError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(output, end="" if output.endswith("\n") else "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
