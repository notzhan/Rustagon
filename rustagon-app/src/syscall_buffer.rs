pub fn configure_syscall_buffer_num(
    modern_ebpf: bool,
    cpus_per_buffer: usize,
    online_cpus: usize,
) -> usize {
    if modern_ebpf && cpus_per_buffer > online_cpus {
        online_cpus
    } else {
        cpus_per_buffer
    }
}
