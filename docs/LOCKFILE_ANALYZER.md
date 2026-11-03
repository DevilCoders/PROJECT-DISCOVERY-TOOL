# Dependency Resolution and Lockfiles

The offline lockfile analyzer extracts resolved package/version entries from package-lock.json, composer.lock, Pipfile.lock, Cargo.lock, poetry.lock, yarn.lock, Gemfile.lock and go.sum.

Lockfile entries are evidence of a recorded dependency resolution, not proof that the packages are installed or that the lockfile matches the current manifest. Full resolver semantics, workspace/monorepo constraints, lockfile-to-manifest consistency, transitive license checks and advisory matching remain future work. No package registry or vulnerability service is contacted.
