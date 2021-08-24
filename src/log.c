#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/errno.h>
#include <time.h>
#include <sys/time.h>
#include "log.h"

void logw(int level, const char *fmt,...)
{
	static FILE *_logfile;
	static va_list _vlst;
	static int _log_level=INFO;
	static char _time_fmt[32];
	static char cmn_logw_fn[256];
	static char cmn_logw_tmp[32768];

	char logtime[32];
	time_t CTIME;
	struct tm *LTIME;

	sprintf(cmn_logw_fn,"agent.log");
	if(NULL ==(_logfile = fopen(cmn_logw_fn,"a+")))
	{
		printf("error:%d:%s\n",errno, strerror(errno));
		return;
	}
	else
	{		
		time(&CTIME);
  		LTIME = (struct tm *)localtime(&CTIME);
		strftime(logtime,32,DATE_TIMESTAMP,LTIME);
		sprintf(_time_fmt,"%s",(char *)logtime);

		va_start(_vlst, fmt);
		vsprintf(cmn_logw_tmp,fmt, _vlst);
		va_end(_vlst);

		switch(_log_level){
			case INFO: 
				//TRACE("info");
				fprintf(_logfile,"info,%s:%s",logtime,cmn_logw_tmp);
				break;
			case ERR: 
				fprintf(_logfile,"error,%s:%s",logtime,cmn_logw_tmp);
				//TRACE("error");
				break;
			case DBG: 
				//TRACE("debug");
				fprintf(_logfile,"debug,%s:%s",logtime,cmn_logw_tmp);
				break;
			default: break;
		}
		fflush(_logfile);
		fclose(_logfile);
	}
	return;
}

void checkLogfile(){
	return;
}

int removeLogFile()
{
	return 0;
}