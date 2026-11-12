"""Tenant isolation engine (architecture §4).

Each tenant gets its own identities, filesystem tree, systemd-sandboxed
PHP-FPM master and cache server in its own cgroup slice, an AppArmor profile,
a database account limited to its own databases, and UID-based network egress
policy (installed by the firewall role).
"""
