/*
 * Copyright (c) 2011, Svante Kvarnström <sjk@ankeborg.nu>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification,
 * 
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.  Redistributions in binary
 * form must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with
 * the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>

char *get_home_directory(void);
void sjk_asprintf(char **, const char *, ...);
char *mkdate(void);

/*
 * This program simply compares $SSH_ORIGINAL_COMMAND to the entries listed in
 * ~/.ssh/validatecmd.conf. If there is a match $SSH_ORIGINAL_COMMAND is 
 * executed. If there is no match the user will be informed. In either case 
 * the execution attempts are logged into ~/.ssh/validatecmd.log.
 */
int
main(void)
{
	FILE *log;						/* Log file handler */
	FILE *conf;						/* Conf file handler */
	char *ssh_original_command;		/* Command user wants to issue */
	char buf[512];					/* Fgets (conf) line buffer */
	char *logfile;					/* File to log to */
	char *conffile;					/* Config file to read */
	int command_ok = 0;				/* 1 if command is OK to execute, 0 if not. */
	int len;
	char *p;

	ssh_original_command = getenv("SSH_ORIGINAL_COMMAND");

	if (ssh_original_command == NULL) {
		fprintf(stderr, "No SSH_ORIGINAL_COMMAND. Exiting...\n");
		return 0;
	}

	sjk_asprintf(&logfile, "%s/.ssh/validatecmd.log", get_home_directory());

	if ((log = fopen(logfile, "a")) == NULL) {
		perror("Could not open log");
		return 1;
	}

	free(logfile);

	sjk_asprintf(&conffile, "%s/.ssh/validatecmd.conf", get_home_directory());

	if ((conf = fopen(conffile, "r")) == NULL) {
		perror("Could not open conf");
		return 1;
	}

	free(conffile);

	while ((p = fgets(buf, sizeof(buf), conf)) != NULL) {
		if (*p == '#') 
			continue;

		if ((strchr(p, '\n')) == NULL) {
			fprintf(stderr, "Ignoring huge config line\n");
			continue;
		}
		
		len = strlen(p)-1;
		if (p[len] == '\n')
			p[len] = '\0';

		if (strcmp(ssh_original_command, p) == 0 || strcmp(p, "*") == 0) {
			command_ok = 1;
			break;
		}
	}

	if (command_ok) {
		fprintf(log, "%s: Executed %s\n", mkdate(), ssh_original_command);
		system(ssh_original_command);
	} else {
		fprintf(log, "%s: Denying command %s\n", mkdate(), ssh_original_command);
		printf("You may not run %s\n", ssh_original_command);
	}

	return 0;
}

/* 
 * asprintf() that exits upon error.
 */
void
sjk_asprintf(char **ret, const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vasprintf(ret, fmt, va);
	if (*ret == NULL) {
		perror("sjk_asprintf");
		exit(1);
	}
	va_end(va);
}

/*
 * Returns user home directory.
 */
char *
get_home_directory(void) 
{
	struct passwd *passwd;
	passwd = getpwuid(getuid());
	return passwd->pw_dir;
}

/*
 * Returns string YYYY-MM-DD HH:SS UTC(+/-)HH.
 */
char
*mkdate(void)
{
    struct tm *tm_ptr;
    time_t the_time;
    char buf[256];
    char *our_date;

    (void)time(&the_time);
    tm_ptr = gmtime(&the_time);

    strftime(buf, sizeof(buf), "%y-%m-%d %H:%M UTC%z", tm_ptr);

    if ((our_date = malloc(strlen(buf) + 1)) == NULL) {
        perror("mkdate() could not malloc");
        exit(1);
    }

    strcpy(our_date, buf);

    return our_date;
}

