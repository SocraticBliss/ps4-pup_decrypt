
#include "debug.h"
#include "defines.h"
#include "kernel_utils.h"

time_t prevtime;
int sock;

uint8_t GetElapsed(uint64_t ResetInterval) {

    time_t currenttime = time(0);
    uint64_t elapsed = currenttime - prevtime;

    if ((ResetInterval == 0) || (elapsed >= ResetInterval)) {
        prevtime = currenttime;
        return 1;
    }

    return 0;
}

void decrypt_pups();

int _main(void)
{
    initKernel();
    initLibc();
    initNetwork();
    initPthread();

#ifdef DEBUG_SOCKET

    // Create our TCP server
    struct sockaddr_in server;
    server.sin_len = sizeof(server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = DEBUG_ADDR;                    // in defines.h
    server.sin_port = sceNetHtons(DEBUG_PORT);              // in defines.h
    memset(server.sin_zero, 0, sizeof(server.sin_zero));
    
    int flag = 1;
    
    sock = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
    sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));
    sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

    printfsocket("Connected!");

#endif

    uint64_t fw_version = get_fw_version();

    // Patch some things in the kernel (sandbox, prison) to give userland more privileges
    jailbreak(fw_version);

    // Need the browser to have been jailbroken first
    initSysUtil();

    printfsocket("PUP Decrypt started!\n");
    GetElapsed(0);

    decrypt_pups("/mnt/usb0/safe.PS4UPDATE.PUP", "/mnt/usb0/%s.dec");

    printfsocket("Bye!\n");

#ifdef DEBUG_SOCKET

    sceNetSocketClose(sock);

#endif

    return 0;
}
