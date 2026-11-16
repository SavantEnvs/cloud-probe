// Fuzzes cpworker's JSON configuration parser (config.c over the bundled cJSON), plus the two
// helpers that consume a parsed config: the BPF output-host exclusion and the snaplen lookup.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "errorf.h"
#include "log.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    log_set_level(LOG_FATAL + 1);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *json = malloc(size + 1);
    if (!json)
        return -1;
    memcpy(json, data, size);
    json[size] = '\0';

    cJSONParseError err;
    memset(&err, 0, sizeof(err));
    Config *cfg = parse_config_data(json, &err);
    free(json);
    if (!cfg)
        return -1;

    char errbuf[ERROR_BUFFER_SIZE];
    char *bpf = bpf_filter_exclude_task_output_hosts("tcp port 80", cfg->tasks_cfg, errbuf);
    free(bpf);
    for (int i = 0; i < cfg->tasks_cfg->num_tasks; i++)
        (void)task_capturer_snaplen(cfg->tasks_cfg->tasks[i]);

    free_config(cfg);
    return 0;
}
