<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2024-2026 AegisGate Security, LLC -->

# Developer Certificate of Origin (DCO)

By making a contribution to this project, I certify that:

1. The contribution was created in whole or in part by me and I have the right to submit it under the open-source license indicated in the file; **or**

2. The contribution is based upon previous work that, to the best of my knowledge, is covered under an appropriate open-source license and I have the right under that license to submit that work with modifications, whether created in whole or in part by me, under the same open-source license (unless I am permitted to submit under a different license); **or**

3. The contribution was provided directly to me by some other person who certified (1), (2), or (3) and I have not modified it.

4. I understand and agree that this project and the contribution are public and that a record of the contribution — including all personal information I submit with it, including my sign-off — is maintained indefinitely and may be redistributed consistent with this project or the open-source license(s) involved.

---

## How to Sign Off

Every commit must include a `Signed-off-by` line certifying the above. This is the same process used by the Linux kernel, Git, and many CNCF projects.

### Using `git commit -s`

The easiest way is to add the `-s` (or `--signoff`) flag when committing:

```bash
git commit -s -m "feat: add rate-limiting middleware"
```

This automatically appends:

```
Signed-off-by: Your Name <your.email@example.com>
```

Your name and email must match your Git configuration:

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

### Manual Sign-Off

If you forgot `-s`, you can amend the commit:

```bash
git commit --amend -s
```

Or add it manually to the commit message body:

```
feat: add rate-limiting middleware

Implemented token-bucket rate limiter for API gateway endpoints.

Signed-off-by: Your Name <your.email@example.com>
```

### Corporate Contributions

If you are contributing on behalf of your employer, you must use your corporate email address in the sign-off. You are personally certifying that your employer has authorized the contribution under the terms of the DCO.

### CI Enforcement

Our CI pipeline automatically verifies that every commit in a pull request includes a valid `Signed-off-by` line. PRs with unsigned commits will fail CI and cannot be merged.

---

*This DCO is based on the [Developer Certificate of Origin 1.1](https://developercertificate.org/) used by the Linux kernel and many open-source projects.*