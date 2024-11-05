# ping -I enp0s3 google.es
# sudo cat /sys/kernel/debug/tracing/trace_pipe
# sudo python3 socket-runner.py
from bcc import BPF

# Programa eBPF en C
bpf_program = """
BPF_HASH(packet_count, u32, u64);

int count_packets(struct __sk_buff *skb) {
    u32 key = 0;
    u64 *count, value = 1;
    count = packet_count.lookup_or_init(&key, &value);
    if (count) {
        __sync_fetch_and_add(count, 1);
	        bpf_trace_printk("Tamany del paquete: %d bytes\\n", skb->len);
    }
    return 0;
}
"""

# Cargar el programa BPF
b = BPF(text=bpf_program)
function = b.load_func("count_packets", BPF.SOCKET_FILTER)

# Adjuntar el programa a una interficie
b.attach_raw_socket(function, "enp0s3")

print("Monitorig.")
try:
    while True:
        key = b["packet_count"].Key(0)
        count = b["packet_count"].get(key, 0)
        print(f"Nombre de paquets: {count}")
except KeyboardInterrupt:
    pass

