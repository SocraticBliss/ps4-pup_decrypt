#include "ps4.h"
#include "defines.h"
#include "debug.h"
#include "kernel_utils.h"

void notify(char *message)
{
    char buffer[512];
    sprintf(buffer, "%s\n\n\n\n\n\n", message);
    sceSysUtilSendSystemNotificationWithText(0x81, buffer);
}

time_t prevtime;

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

int sock;

int _main(void)
{
  initKernel();
  initLibc();
  initNetwork();
  initPthread();

#ifdef DEBUG_SOCKET
  struct sockaddr_in server;

  server.sin_len = sizeof(server);
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = DEBUG_ADDR;                //in defines.h
  server.sin_port = sceNetHtons(DEBUG_PORT);          //in defines.h
  memset(server.sin_zero, 0, sizeof(server.sin_zero));
  sock = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
  sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));

  int flag = 1;
  sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
#endif

  uint64_t fw_version = get_fw_version();

  jailbreak(fw_version); // Patch some things in the kernel (sandbox, prison) to give to userland more privileges

  initSysUtil();

  notify("PUP Decrypt started!");
  printfsocket("PUP Decrypt started!\n");

  GetElapsed(0);

  //decrypt_pups(NULL, NULL); //use define.h

  //Output paths must already exist!
  decrypt_pups("/mnt/usb0/safe.PS4UPDATE.PUP", "/mnt/usb0/%s.dec");

  notify("Complete!");
  printfsocket("Bye!\n");

#ifdef DEBUG_SOCKET
  sceNetSocketClose(sock);
#endif
  return 0;
}
