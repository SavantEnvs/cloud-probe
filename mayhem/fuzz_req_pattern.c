// Fuzzes the custom request-pattern matcher: the `host ... and port ...` expression parser/AST, then the
// direction judgement over a captured frame. Input: pattern text, a NUL byte, then an Ethernet frame.
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "errorf.h"
#include "log.h"
#include "req_pattern.h"

static int fake_get_if_ip_addr(const char *ifname, ip_addr_t *addr, char *errbuf)
{
    if (strcmp(ifname, "eth0") == 0)
    {
        addr->type = IP_TYPE_IPv4;
        inet_pton(AF_INET, "172.16.1.1", &addr->data.v4);
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
    const uint8_t *nul = memchr(data, '\0', size);
    size_t pat_len = nul ? (size_t)(nul - data) : size;
    const uint8_t *frame = nul ? nul + 1 : data + size;
    size_t frame_len = nul ? size - pat_len - 1 : 0;

    char *pattern = malloc(pat_len + 1);
    if (!pattern)
        return -1;
    memcpy(pattern, data, pat_len);
    pattern[pat_len] = '\0';

    req_pattern_t rp;
    memset(&rp, 0, sizeof(rp));
    rp.type = REQ_PATTERN_TYPE_CUSTOM;
    int rc = req_pattern_custom_matcher_init(&rp.matcher.custom, pattern, fake_get_if_ip_addr);
    free(pattern);
    if (rc != 0)
        return -1;

    uint8_t *pkt = malloc(frame_len ? frame_len : 1);
    if (!pkt)
    {
        req_pattern_custom_matcher_destroy(&rp.matcher.custom);
        return -1;
    }
    memcpy(pkt, frame, frame_len);
    struct pcap_pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.caplen = hdr.len = (uint32_t)frame_len;
    (void)req_pattern_judge_pkt_direction(&rp, &hdr, pkt);

    free(pkt);
    req_pattern_custom_matcher_destroy(&rp.matcher.custom);
    return 0;
}
