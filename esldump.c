#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <sys/wait.h>
#include <pcap.h>
#include <jansson.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define BOLDGREEN   "\033[1;32m"
#define NOCOLOR     "\033[0m"

static const char *esl_hdrs[] = {
    "Core-UUID",
    "FreeSWITCH-Hostname",
    "FreeSWITCH-Switchname",
    "FreeSWITCH-IPv4",
    "FreeSWITCH-IPv6",
    "Event-Date-Local",
    "Event-Date-GMT",
    "Event-Date-Timestamp",
    "Event-Calling-File",
    "Event-Calling-Function",
    "Event-Calling-Line-Number",
    "profile-name",
    "from-user",
    "from-host",
    "contact",
    "rpid",
    "status",
    "auth-status",
    "fail-reason",
    "expires",
    "to-user",
    "to-host",
    "network-ip",
    "network-port",
    "username",
    "realm",
    "sip-method",
    "user-agent",
    "limit-usage",
    "limit-max",
    "limit-seconds",
    "limit-host"
};
static const size_t esl_hdr_len = sizeof(esl_hdrs) / sizeof(esl_hdrs[0]);

static inline const struct tcphdr *get_tcp(const uint8_t *data, const uint8_t **payload)
{
    const struct tcphdr* hdr = (const struct tcphdr *)data;
    *payload = &data[hdr->th_off * 4];
    return hdr;
}

static inline const struct ip *get_ip(const uint8_t *data, const uint8_t **payload)
{
    const struct ip* hdr = (const struct ip *)data;
    *payload = &data[hdr->ip_hl * 4];
    return hdr;
}

static pcap_t *pcap_start(const char *filename)
{
    char err[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_offline(filename, err);
    if (!handle)
        errx(1, "couldn't open pcap file %s", filename);

    return handle;
}

static pid_t pager_start(const char *mode)
{
    int pipefd[2];

    if (!isatty(STDOUT_FILENO))
        return 0;

    if (pipe2(pipefd, O_CLOEXEC) < 0)
        err(1, "failed to create pipe");

    pid_t pid = fork();
    switch (pid) {
    case -1:
        err(1, "failed to fork");
        break;
    case 0:
        setenv("LESS", mode, true);
        dup2(pipefd[STDIN_FILENO], STDIN_FILENO);
        execlp("less", "less", NULL);
        err(1, "failed to start pager");
        break;
    }

    dup2(pipefd[STDOUT_FILENO], STDOUT_FILENO);
    close(pipefd[0]);
    close(pipefd[1]);

    return pid;
}

static int pager_wait(pid_t pid)
{
    int stat;

    fflush(stdout);
    fclose(stdout);

    if (waitpid(pid, &stat, 0) < 0)
        err(1, "Failed to get pager status");

    if (stat) {
        if (WIFEXITED(stat))
            return WEXITSTATUS(stat);
        if (WIFSIGNALED(stat))
            return -1;
    }

    return 0;
}

static json_t *extract_json(const uint8_t *payload, size_t len)
{
    json_t *json;
    json_error_t error;

    uint8_t *start = memchr(payload, '{',  len);
    if (!start)
        return NULL;

    len -= start - payload;
    json = json_loadb((char *)start, len, 0, &error);

    if (!json)
        warnx("error on line %d: %s\n", error.line, error.text);
    return json;
}

static int print_header(const json_t *root)
{
    const json_t *name, *class;

    name = json_object_get(root, "Event-Name");
    if (!json_is_string(name))
        return -1;

    class = json_object_get(root, "Event-Subclass");
    if (!json_is_string(class))
        return -1;

    printf(BOLDGREEN "%s" NOCOLOR " from %s\n",
           json_string_value(name), json_string_value(class));

    return 0;
}

static int print_field(const json_t *root, const char *key)
{
    const json_t *value = json_object_get(root, key);
    if (!json_is_string(value))
        return -1;

    printf("%26s: %s\n", key, json_string_value(value));
    return 0;
}

int main(int argc, char *argv[])
{
    int i;
    pcap_t *handle;
    const uint8_t *packet;
    struct pcap_pkthdr header;

    if (argc == 1) {
        fprintf(stderr, "usage: %s [files...]\n", argv[0]);
        return 1;
    }

    pid_t pager = pager_start("FRSX");

    for (i = 1; i < argc; ++i) {
        handle = pcap_start(argv[i]);

        while ((packet = pcap_next(handle, &header))) {
            const uint8_t *payload;

            const struct ip *ipheader = get_ip(packet + 14, &payload);
            if (ipheader->ip_v != IPVERSION)
                continue;
            if (ipheader->ip_p != IPPROTO_TCP)
                continue;

            const struct tcphdr *tcpheader = get_tcp(payload, &payload);
            if (tcpheader->th_sport != htons(8021))
                continue;
            if (!(tcpheader->th_flags & TH_PUSH))
                continue;

            size_t payload_len = header.caplen - (payload - packet);
            json_t *root = extract_json(payload, payload_len);

            if (!root)
                continue;

            print_header(root);

            size_t idx;
            for (idx = 0; idx < esl_hdr_len; ++idx)
                print_field(root, esl_hdrs[idx]);
            putchar('\n');

            json_decref(root);
        }

        pcap_close(handle);
    }

    return pager ? pager_wait(pager) : 0;
}
