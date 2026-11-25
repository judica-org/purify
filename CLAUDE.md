# Working in this repository

## Pull requests

- Open every pull request on `judica-org/purify` against `master`.
- Do not open a pull request against any other base branch.
- Do not open a pull request inside a fork such as `JeremyRubin/purify`. A fork
  may hold the head branch. It is never the base.
- Do not stack pull requests. When work depends on an unmerged pull request,
  add the commits to that pull request, or wait for it to merge and rebase onto
  `master`. If neither works, stop and ask.
- Before starting work, run `git fetch --all` and check that the checkout is
  based on the current `master` of `judica-org/purify`. If it is on some other
  line, say so before building on it.
- After a pull request merges, confirm that its commits are on master:
  `git merge-base --is-ancestor <sha> <judica-org remote>/master`.

Why: pull request #61 (45 commits) was opened against a work branch and merged
there. Master never received it. Later work, including a second pull request
opened inside the fork, was built on that line while master moved on without
it, and the two had to be reconciled by hand.
