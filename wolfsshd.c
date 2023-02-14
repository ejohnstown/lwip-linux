
#include "wolfsshd.h"

#include "lwip/opt.h"

#if LWIP_SOCKET && (LWIP_IPV4 || LWIP_IPV6)

#include "lwip/sockets.h"
#include "lwip/netif.h"
#include "lwip/etharp.h"
#include "lwip/tcpip.h"
#include "netif/tapif.h"
//#include "lwip/sys.h"

//#include "lwip/posix/sys.h"

#include <string.h>
#include <stdio.h>

#ifndef SOCK_TARGET_HOST4
#define SOCK_TARGET_HOST4  "192.168.2.1"
#endif

#define TAPDEV_IP "192.168.2.102"
#define TAPDEV_NETMASK "255.255.255.0"
#define TAPDEV_GW "192.168.2.1"

#ifndef SSHD_PORT
#define SSHD_PORT  22
#endif

#define MAX_SERV 3

#include "ssh_auth.h"


/* Sample buffer for passwords */
static const char samplePasswordBuffer[] =
    "jill:upthehill\n"
    "jack:fetchapail\n";


/* Sample buffer with public keys */
static const char samplePublicKeyEccBuffer[] =
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAA"
    "BBBNkI5JTP6D0lF42tbxX19cE87hztUS6FSDoGvPfiU0CgeNSbI+aFdKIzTP5CQEJSvm25"
    "qUzgDtH7oyaQROUnNvk= hansel\n"
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAA"
    "BBBKAtH8cqaDbtJFjtviLobHBmjCtG56DMkP6A4M2H9zX2/YCg1h9bYS7WHd9UQDwXO1Hh"
    "IZzRYecXh7SG9P4GhRY= gretel\n";


/* Maximum parallel sessions */
#define MAX_SSH_SESSIONS 4

struct ssh_client_socket {
	int fd;
	WOLFSSH *ssh;
	int is_sftp;
	int is_interactive;
};

static struct ssh_client_socket ssh_session[MAX_SSH_SESSIONS];

static int ssh_get_session(int fd)
{
	int i;
	for (i = 0; i < MAX_SSH_SESSIONS; i++) {
		if (ssh_session[i].fd == fd)
			return i;
	}
	return -1;
}

static void ssh_init_sessions(void)
{
	int i;
	for (i = 0; i < MAX_SSH_SESSIONS; i++)
		ssh_session[i].fd = -1;
}

static int ssh_avail_session(void)
{
	int i;
	for (i = 0; i < MAX_SSH_SESSIONS; i++) {
		if (ssh_session[i].fd == -1)
			return i;
	}
	return -1;
}
static int ssh_interactive_mode_active(void)
{
	int i;
	for (i = 0; i < MAX_SSH_SESSIONS; i++)
	{
		if ((ssh_session[i].fd != -1) && (ssh_session[i].is_interactive == 1))
			return 1;
	}
	return 0;
}

static int ssh_sftp_session_active(void)
{
	int i;
	for (i = 0; i < MAX_SSH_SESSIONS; i++)
	{
		if ((ssh_session[i].fd != -1) && (ssh_session[i].is_sftp == 1))
			return 1;
	}
	return 0;
}

static const char serverBanner[] = "wolfSSH Server\n";


/* Dimensions the buffer into which input characters are placed. */
#define CLI_CMD_MAX_INPUT_SIZE              (64)
#define CLI_CMD_MAX_OUTPUT_SIZE              (64)

/* Dimensions the buffer passed to the recv or recvfrom() call. */
#define CLI_CMD_SOCKET_INPUT_BUFFER_SIZE    (64)

#define CLI_SERVER_THREAD_PRIORITY          (TCPIP_THREAD_PRIO + 1)
#define CLI_KEEPALIVE_INTERVAL_TIME         (60) // Keepalive interval time in second
#define CLI_KEEPALIVE_PACKET_COUNT          (30) // Keepalive max packet count


static ip_addr_t local_addr;

static void ssh_client_connected(int lClientSocket)
{
    signed char cInChar, cInputIndex = 0;
    static char cInputString[CLI_CMD_MAX_INPUT_SIZE];
    static char cOutputString[CLI_CMD_MAX_OUTPUT_SIZE];
    static char cLocalBuffer[CLI_CMD_SOCKET_INPUT_BUFFER_SIZE];
    const char CLI_PROMPT_STRING[] = "> ";
    word32 xBytes, xByte;
    int lSocket, lServerSocket;
    struct timeval xTimeout;
    int iResult;
    const char *session_cmd = NULL;
    int idx, ret;
    WOLFSSH_CTX* ctx = NULL;
    WOLFSSH *ssh = NULL;
    PwMapList pwMapList;
    word32 bufSz = 0;
    printf("CLI - Client (socket:%d) is connected\n", lClientSocket);
    idx = ssh_avail_session();
    if (idx < 0) {
        printf("CLI - Too many SSH connections, closing.\n");
        lwip_close(lClientSocket);
        return;
    }
    ssh_session[idx].fd = lClientSocket;
    ssh = wolfSSH_new(ctx);
    ssh_session[idx].ssh = ssh;
    ssh_session[idx].is_sftp = 0;
    ssh_session[idx].is_interactive = 0;
    if (ssh == NULL) {
        printf( "Couldn't allocate SSH session data.\n");
        lwip_close(lSocket);
        return;
    }
    /* Associate map list as context for the auth callback */
    wolfSSH_SetUserAuthCtx(ssh, &pwMapList);

    /* Associate TCP socket to the SSH session */
    wolfSSH_set_fd(ssh, (int)lClientSocket);

    /* Accept SSH session */
    ret = wolfSSH_accept(ssh);
    if (ret == WS_SFTP_COMPLETE) {
        if (ssh_sftp_session_active()){
            printf("Only one SFTP session allowed at one time. Closing...\n");
            lwip_close(lClientSocket);
            return;
        }
        printf("SFTP client connected\n");
        ssh_session[idx].is_sftp = 1;
        return;
    }
    if (ret != WS_SUCCESS) {
        printf("wolfSSH_accept: error %d\n\n", ret);
        lwip_close(lClientSocket);
        return;
    }
    printf("SSH client connected\n");
    session_cmd = wolfSSH_GetSessionCommand(ssh);
    if (session_cmd) {
        printf("Command mode\n");
        /* Process the input string received as exec command in the handshake */
        const char cOutputString[] = "I hear you!\r\n";
        printf("Received command: %s\n", session_cmd);
        /* Send the output generated by the command's implementation. */
        wolfSSH_stream_send(ssh, (byte *)cOutputString, strlen(cOutputString));

        /* Nothing else to do. Disconnect. */
        lwip_close(lClientSocket);
        return;
    }
    printf("Interactive mode\n");
    if (ssh_interactive_mode_active()) {
        const char too_many_conn_msg[] = "Too many interactive connections.\r\n";
        printf("Only one interactive session allowed at one time. Closing...\n");
        wolfSSH_stream_send(ssh, (byte*)too_many_conn_msg, strlen(too_many_conn_msg));
        lwip_close(lClientSocket);
    } else {
        ssh_session[idx].is_interactive = 1;
    }
    /* Transmit a spacer, just to make the command console easier to read. */
    wolfSSH_stream_send(ssh, (byte *)CLI_PROMPT_STRING,  strlen(CLI_PROMPT_STRING));
    for (;;) {
        if (ssh_session[idx].is_sftp) {
            int ret;
            int err;
            do {
                unsigned char peek_buf[1];
                ret = wolfSSH_SFTP_read(ssh);
                if (ret < 0)
                    break;
                ret = wolfSSH_stream_peek(ssh, peek_buf, 1);
                if (ret <= 0)
                    break;
            } while(ret >= 0);
            err = wolfSSH_get_error(ssh);
            if (ret == WS_FATAL_ERROR && err == 0) {
                WOLFSSH_CHANNEL* channel =
                    wolfSSH_ChannelNext(ssh, NULL);
                if (channel && wolfSSH_ChannelGetEof(channel)) {
                    ret = 0;
                    printf("SFTP - Connection terminated.\n");
                    lwip_close(lSocket);
                }
            }
            continue;
        }
        xBytes = wolfSSH_stream_read(ssh, (byte *)cLocalBuffer, sizeof(cLocalBuffer));
        if (xBytes < 0)
        {
            int err;
            err = wolfSSH_get_error(ssh);
            if (err != WS_WANT_READ)
            {

                lwip_close(lSocket);
                printf("CLI - SSH receive error: %s.\nClient (socket:%d) is disconnected\n",
                        wolfSSH_ErrorToName(err), lSocket);

            }
        }
        else if (xBytes == 0)
        {
            lwip_close(lSocket);
            printf("CLI - Client (socket:%d) is disconnected\n", lSocket);
        }
        else
        {
            xByte = 0;
            while (xByte < xBytes)
            {
                /* The next character in the input buffer. */
                cInChar = cLocalBuffer[xByte];
                xByte++;
                if (cInChar == 0x03) { /* CTRL+C */
                    wolfSSH_stream_send(ssh, (byte *)"\r\n", 2);
                    wolfSSH_stream_send(ssh, (byte *)"CTRL+C", 6);
                    wolfSSH_stream_send(ssh, (byte *)"\r\n", 2);
                    printf("Received CTRL+C: Client %d is disconnected\n", lSocket);
                    lwip_close(lSocket);
                    break;
                }
                if (cInChar == 0x04) { /* CTRL+D */
                    wolfSSH_stream_send(ssh, (byte *)"\r\n", 2);
                    wolfSSH_stream_send(ssh, (byte *)"CTRL+D", 6);
                    wolfSSH_stream_send(ssh, (byte *)"\r\n", 2);
                    printf("Received CTRL+D: Client %d is disconnected\n", lSocket);
                    lwip_close(lSocket);
                    break;
                }
                if (cInChar == 0x06) { /* ACK == Rekey */
                    printf("Received REKEY\n");
                    if (wolfSSH_TriggerKeyExchange(ssh)
                            != WS_SUCCESS) {
                        lwip_close(lSocket);
                        break;
                    }
                }
                /* Clear the input buffer if the input character is not ASCII */
                if (!isascii(cInChar))
                {
                    printf("CLI - Server input isn't ASCII so ignore and clear input buffer\n");
                    cInputIndex = 0;
                    break;
                }
                /* Send back only printable characters */
                if (cInChar >= ' ' && cInChar < 0x7F)
                    wolfSSH_stream_send(ssh, (byte *)&cInChar, 1);

                /* CR characters are taken as the end of the command string. */
                if (cInChar == '\r')
                {
                    const char crlf[]="\r\n";
                    const char cOutputString[] = "OK!\r\n";
                    /* CR-LF back to client */
                    wolfSSH_stream_send(ssh, (byte *)crlf, 2);

                    /* Process the input string received prior to the newline. */
                    printf("Received interactive command: %s\n", cInputString);
                    /* Send the output generated by the command's implementation. */
                    wolfSSH_stream_send(ssh, (byte *)cOutputString, strlen(cOutputString));

                    /* All the strings generated by the command processing have been sent.  Clear the input string
                       ready to receive the next command. */
                    cInputIndex = 0;
                    memset(cInputString, 0x00, CLI_CMD_MAX_INPUT_SIZE);

                    /* Transmit a spacer, just to make the command console easier to read. */
                    wolfSSH_stream_send(ssh, (byte *)CLI_PROMPT_STRING, strlen(CLI_PROMPT_STRING));
                }
                else
                {
                    if (cInChar == '\n')
                    {
                        /* Ignore the character.  CR are used to detect the end of the input string. */
                    }
                    else if ((cInChar == '\b') || (cInChar == 0x7F))
                    {
                        /* Backspace was pressed.  Erase the last character in the string - if any. */
                        if (cInputIndex > 0)
                        {
                            cInputIndex--;
                            cInputString[cInputIndex] = '\0';
                            wolfSSH_stream_send(ssh, (byte *) "\b \b", 3);
                        }
                    }
                    else
                    {
                        /* A character was entered.  Add it to the string entered so far. When a \n is entered
                           the complete string will be passed to the command interpreter. */
                        if (cInputIndex < CLI_CMD_MAX_INPUT_SIZE)
                        {
                            cInputString[cInputIndex] = cInChar;
                            cInputIndex++;
                        }
                    }
                }
            }
        }
    }
}


sshd(void)
{
    int s;
    struct sockaddr_in saddr;
    s = lwip_socket(AF_INET, SOCK_STREAM, 0);
    LWIP_ASSERT("s >= 0", s >= 0);
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = PP_HTONS(SSHD_PORT);
    saddr.sin_addr.s_addr = PP_HTONL(INADDR_ANY);
    if (lwip_bind(s, (struct sockaddr *) &saddr, sizeof (saddr)) == -1) {
        LWIP_ASSERT("wolfsshd: Socket bind failed.", 0);
    }
    /* Put socket into listening mode */
    if (lwip_listen(s, MAX_SERV) == -1) {
        LWIP_ASSERT("wolfsshd: Listen failed.", 0);
    }
    for (;;) {
        int conn_sd;
        ip_addr_t cli_addr;
        word32 socklen = sizeof(cli_addr);
        conn_sd = lwip_accept(s, &cli_addr, &socklen);
        if (conn_sd < 0) {
            sleep(1);
            continue;
        }
        ssh_client_connected(conn_sd);
    }
}


#ifndef NO_MAIN
int main(int argc, char *argv[])
{
    //lwip_init();
    tcpip_init(NULL, NULL);
    wolfsshds_init();
    sshd();
}
#endif

static struct netif tapif;
static ip4_addr_t a4, nm4, gw4;
void wolfsshds_init(void)
{
    int addr_ok;
    ip_addr_t nma, gwa;

    memset(&tapif, 0, sizeof(tapif));
    IP_SET_TYPE_VAL(local_addr, IPADDR_TYPE_V4);
    addr_ok = ip4addr_aton(TAPDEV_IP, ip_2_ip4(&local_addr));
    LWIP_ASSERT("invalid address", addr_ok);
    ip4addr_aton(TAPDEV_IP, ip_2_ip4(&tapif.ip_addr));
    ip4addr_aton(TAPDEV_NETMASK, ip_2_ip4(&tapif.netmask));
    ip4addr_aton(TAPDEV_GW, ip_2_ip4(&tapif.gw));
    tapif.output = etharp_output;
    tapif.mtu = 1500;
    tapif.flags = NETIF_FLAG_ETHARP |NETIF_FLAG_BROADCAST;
    a4.addr = tapif.ip_addr.addr;
    nm4.addr = tapif.netmask.addr;
    gw4.addr = tapif.gw.addr;
    netif_add(&tapif, &a4, &nm4, &gw4, NULL, tapif_init,
              tcpip_input);

    netif_set_up(&tapif);
    netif_set_link_up(&tapif);
  
}

#endif /* LWIP_SOCKET */
