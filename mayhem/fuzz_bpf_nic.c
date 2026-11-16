// Fuzzes the BPF filter rewriter that substitutes `nic.<ifname>` tokens with that interface's IP address.
// Interface lookup is replaced by a fixed in-process table so the harness needs no network devices.
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bpf_util.h"
#include "errorf.h"
#include "log.h"

static int fake_get_if_ip_addr(const char *ifname, ip_addr_t *addr, char *errbuf)
{
    if (strcmp(ifname, "eth0") == 0)
    {
        addr->type = IP_TYPE_IPv4;
        inet_pton(AF_INET, "172.16.1.1", &addr->data.v4);
        return 0;
    }
    if (strcmp(ifname, "eth1") == 0)
    {
        addr->type = IP_TYPE_IPv6;
        inet_pton(AF_INET6, "fe80::1", &addr->data.v6);
        return 0;
    }
    error_format(errbuf, "interface '%s' not exists", ifname);
    return -1;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    log_set_level(LOG_FATAL + 1);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *bpf = malloc(size + 1);
    if (!bpf)
        return -1;
    memcpy(bpf, data, size);
    bpf[size] = '\0';

    char errbuf[ERROR_BUFFER_SIZE];
    char *out = bpf_filter_replace_nic(bpf, fake_get_if_ip_addr, errbuf);
    free(bpf);
    if (!out)
        return -1;
    free(out);
    return 0;
}
