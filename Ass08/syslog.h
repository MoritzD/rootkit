#ifndef SYSLOG_H
#define SYSLOG_H

extern unsigned int curIP;
extern unsigned short curPort;

void syslog(char* string);
void sendSyslog(char* string);
int init_syslog(void);
void exit_syslog(void);

#endif
