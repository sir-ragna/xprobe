#include "pxprobe.h"
#include "interface_con.h"
#include "cmd_opts.h"
#include "targets_list.h"
#include "config_set.h"
#include "xprobe_module.h"
#include "xprobe_module_hdlr.h"
#include "scan_engine.h"
#include "os_matrix.h"
#include "log.h"
#include "pxprobe.h"

Interface *ui;

/*
 * argh...globals...due to not so good design of xprobe2
 * need to declare following dummy global variables in
 * order to be able to reuse the classes of xprobe2
 */
Cmd_Opts			*copts;
Targets_List		*targets;
Config_Set			*cfg;
Xprobe_Module_Hdlr	*xmh;
Scan_Engine			*se;
OS_Name				*oses;
XML_Log				*xml;

void pxprobe_usage(char *);

int main(int argc, char **argv) {
	Targets_List tgs;
	AsyncOutputReader async;
	PxprobeOutputProcessor outproc;
	vector<CommandExecutor *> execs;
	string cmd = DEFAULT_COMMAND;
	int c, numOfProcs=-1;
	
	ui = new Interface_Con;

	ui->msg(PXPROBE_BANNER);
	while ((c=getopt(argc, argv, "p:c:")) != EOF) {
		switch(c) {
			case 'p':
				numOfProcs = atoi(optarg);
				break;
			case 'c':
				cmd = optarg;
				break;
			default:
				pxprobe_usage(argv[0]);

		}
	}
	if (numOfProcs < 1)
		pxprobe_usage(argv[0]);
	if (argc < optind + 1) 
		pxprobe_usage(argv[0]);
	tgs.init(argv[optind]);

	for (int i=0; i < numOfProcs; i++) {
		execs.push_back(new PopenCommandExecutor());
	}
	async.registerProcessor(&outproc);
	async.run(tgs, execs, cmd);
	return 0;
}

void pxprobe_usage(char *name) {
	ui->error("%s: usage -p <numofprocs> [-c <command>] <target specification>\n", name);
	exit(1);
}
