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

Pull Request Checklist
----------------------
- [ ] My commits are signed off with DCO (`Signed-off-by:`)
- [ ] I agree my contribution is GPL-3.0-or-later
- [ ] I grant maintainers the right to relicense my contribution under
      AGPL-3.0-or-later or another OSI-approved license used by PRAHO
- [ ] Tests pass locally / CI green

How to build and test
---------------------
- Platform: see `services/platform/README` or repo `README.md` for setup.
- Portal: see `services/portal/README` or repo `README.md` for setup.

Security
--------
Please report vulnerabilities privately to the maintainers. Do not open a
public issue for security-sensitive matters.
