package common.secrets

is_stale(date) if {
    diff := time.diff(time.now_ns(),date)
    diff[0] >= 1
}
