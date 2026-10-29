Contributing to PRAHO
=====================

Thank you for considering a contribution! This document explains how to
contribute code and what legal terms apply to your contribution so we can
keep licensing options flexible in the future.

Code of Conduct
---------------
Be kind and professional. Report unacceptable behavior to the maintainers.

License of contributions (Inbound = Outbound)
---------------------------------------------
By submitting a contribution (pull request, patch, etc.), you agree that your
contribution is licensed under the project’s license:

- GPL-3.0-or-later for the PRAHO repository

Contributor License Grant (relicensing permission)
--------------------------------------------------
In addition, you grant the PRAHO maintainers a perpetual, worldwide,
non-exclusive, no-charge, royalty-free, irrevocable license to relicense your
contribution, as part of PRAHO, under AGPL-3.0-or-later or another
OSI-approved license used by the project in the future. This is solely to keep
license options open for the project while ensuring your contribution remains
free software.

Developer Certificate of Origin (DCO)
-------------------------------------
We require the Developer Certificate of Origin 1.1 sign-off on all commits.
This is a lightweight way to certify that you wrote the code or otherwise have
the right to submit it under the project’s license.

- Add a Signed-off-by line to every commit message, e.g.:

  Signed-off-by: Your Name <you@example.com>

- Git can add this automatically with `-s`:

  git commit -s -m "feat: add new API"

Before the first push, verify every commit in the PR range has a sign-off matching
its author. Keep the sign-off when amending or rebasing. A pull request lands as a
squash whose message is its title and description, so the description ends with
your sign-off line too.

Opening a pull request
----------------------
- Branch from `master` and open the pull request against `master`, also when it
  builds on another open pull request.
- Title: a Conventional Commits subject (`fix(billing): ...`). It becomes the subject
  of the squash commit on `master`.
- Description: written as that commit's body. Say what changed and why, add
  `Closes #N` for each issue it closes (a `#N` in the title closes nothing), and end
  with `Signed-off-by: Your Name <you@example.com>`. The DCO check refuses a
  description without it.
- Keep a pull request under about 400 changed lines of code; split larger work into
  pull requests that each stand on their own.
- Add a `CHANGELOG.md` entry for a change users or operators will notice.

Merging is in `docs/development/MERGING.md`.

Pull Request Checklist
----------------------
- [ ] My commits are signed off with DCO (`Signed-off-by:`)
- [ ] The description ends with my `Signed-off-by:` line
- [ ] I agree my contribution is GPL-3.0-or-later
- [ ] I grant maintainers the right to relicense my contribution under
      AGPL-3.0-or-later or another OSI-approved license used by PRAHO
- [ ] Focused tests pass locally, and every required CI check is green

How to build and test
---------------------
The root `Makefile` is the interface for both services. Setup and the full list of targets are in
the repository's `README.md`.

    make install    # dependencies for both services, plus the pre-commit hooks
    make dev        # Platform on :8700, Portal on :8701
    make lint       # every lint phase (CI runs it on each pull request)
    make test       # platform, portal and cross-service suites

Pull request CI is the full gate, and `master` requires every check to pass: platform, portal,
integration, browser and strict-CSP, and DCO. The merge queue runs them again on the merge commit,
with the Virtualmin lab when the change can reach it (see
`docs/ADRs/ADR-0036-tiered-ci-testing-strategy.md` and `docs/development/MERGING.md`). Locally, run what takes seconds on what you
touched: the pre-commit hooks, `make lint FILE=<path>`, `make test-file FILE=<label>` for platform
tests (or `pytest <path>` for portal), and `make check-types FILE=<path>`. There is no need to run
the full gate before pushing; push at logical checkpoints and let CI run it.

Security
--------
Please report vulnerabilities privately to the maintainers. Do not open a
public issue for security-sensitive matters.
