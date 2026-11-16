// Fuzzes the VXLAN output's packet splitter: parse_packet -> calculate_fragment_count -> build_fragment,
// driven the way output_vxlan.c drives it. Input: u16 max_payload_size (LE), u8 flags (bit0 =
// recalculate_checksum), then the raw Ethernet frame.
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "output_vxlan.h"
#include "packet_split.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    log_set_level(LOG_FATAL + 1);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 3)
        return -1;
    int max_payload_size = data[0] | (data[1] << 8);
    bool recalc = data[2] & 1;
    data += 3;
    size -= 3;
    // output_vxlan.c only splits frames longer than a non-zero max_payload_size.
    if (max_payload_size == 0 || size <= (size_t)max_payload_size || size > VXLAN_MAX_FRAME_LEN)
        return -1;

    uint8_t *pkt = malloc(size);
    uint8_t *out = malloc(VXLAN_OUTPUT_BUFSIZE);
    if (!pkt || !out)
    {
        free(pkt);
        free(out);
        return -1;
    }
    memcpy(pkt, data, size);

    packet_parse_result_t pr;
    int rc = -1;
    if (parse_packet(pkt, (uint32_t)size, &pr))
    {
        int n = calculate_fragment_count(&pr, max_payload_size);
        for (int i = 0; i < n && i < 4096; i++)
        {
            int len = build_fragment(&pr, pkt, i, max_payload_size, recalc, out);
            if (len <= 0)
                break;
            rc = 0;
        }
    }
    free(pkt);
    free(out);
    return rc;
}
