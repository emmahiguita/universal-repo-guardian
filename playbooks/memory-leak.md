# Memory Leak Playbook
Baseline memory → identify allocation/owner → identify expected disposal → reproduce cycles → compare heap/native/mmap/FD → patch ownership/cleanup → stress lifecycle → verify plateau.
