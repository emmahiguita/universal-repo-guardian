# Process Zombie Playbook
Map parent/child → capture PID/exit/signal → verify waitpid/SIGCHLD ownership → stop/restart cycles → check no zombies/orphans/stale sockets.
