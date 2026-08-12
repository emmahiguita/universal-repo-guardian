from __future__ import annotations
RULES={
    "network":["reconnect","timeout","disconnect","resource_cleanup"],
    "memory":["lifecycle_stress","heap_growth","fd_growth","native_cleanup"],
    "process":["start_stop_restart","zombie_check","stale_socket","pid_reuse"],
    "render":["frame_pacing","surface_recreate","buffer_backpressure"],
    "database":["transaction","migration","rollback","concurrency"],
    "jni":["symbol_validation","device_runtime","thread_attach","reference_cleanup"],
}
def recommend(category:str):
    low=category.lower()
    for k,v in RULES.items():
        if k in low: return v
    return ["focused_test","adjacent_regression","cleanup"]
