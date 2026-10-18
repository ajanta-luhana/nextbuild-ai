# ADR-0004: Namespace sandbox with refuse-by-default fallback
Generated code runs via `unshare --mount --net --pid --fork --map-root-user` into a tmpfs chroot containing only read-only
bind mounts of `/usr`, `/lib*`, `/bin`, `/sbin` and the run workspace at `/work`. Environment is scrubbed to a fixed set.
rlimits (CPU, file size, open files, address space), a wall-clock timeout with process-group kill, and a 1 MB output cap apply.
At startup the runner *probes* the host by actually running a test inside the sandbox (network unreachable, no `/root`, no
docker socket). If the probe fails, untrusted execution is disabled (`POLICY_BLOCKED / SANDBOX_UNAVAILABLE`) unless the operator
sets `ALLOW_WEAK_SANDBOX=1`, which production configuration rejects.
Known gaps: no cgroup memory/PID limits (rlimits only), shared kernel (not a VM boundary), Linux only.
