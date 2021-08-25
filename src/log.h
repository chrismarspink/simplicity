
#ifndef IVCLOG_H
#define IVCLOG_H

#define NOLOG   0x00
#define INFO    0x01
#define ERR     0x02
#define DBG	    0x04



//#define TRACE(x) fprintf(_logfile,"%s[%5d/%5d][%s] %s", _time_fmt,getpid(),getppid(),x,cmn_logw_tmp);
#define TRACE(x) fprintf(_logfile,"%s,%s:%s", x,_time_fmt,cmn_logw_tmp);
#define DATE_TIMESTAMP "[%Y/%m/%d %H:%M:%S]"
#define DATE_EVENTTIME "%Y%m%d%H%M%S"

char*   getCurrTimeStr();
void    logw(int level, const char *fmt,...);
void    checkLogfile();
int     removeLogFile();

//--static int     log_level;

#endif //IVCLIB_H