# Repository Instructions

- Do not add GitHub Actions workflows. This repository intentionally keeps
  `.github/workflows/` empty.
- Keep the scanner TCP-only. Do not add UDP parsing or scanning unless a user
  explicitly changes the project scope.
- Preserve the exact host-to-port relationships found in the Masscan input;
  never replace them with a host-by-all-ports cross-product.
- Treat individual Nmap XML files as authoritative results. A combined XML
  file is a derived convenience report.
- After completing and validating each requested repository change, commit the
  changes made for that request and push the current branch to its configured
  upstream. Do not include unrelated pre-existing worktree changes in the
  commit.
