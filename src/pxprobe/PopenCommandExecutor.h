#ifndef PXPROBE_POPEN_COMMAND_EXECUTOR_H
#define PXPROBE_POPEN_COMMAND_EXECUTOR_H

#include "xprobe.h"

/*
 * Executes supplied command via popen(), returns
 * descriptor linked to stdout of executed command
 */

class PopenCommandExecutor: public CommandExecutor {
	private:
		FILE *r_pipe;
	public:
		PopenCommandExecutor(): CommandExecutor() {
			r_pipe = NULL;
			setDescriptor(0);
		}
		int execute(string &);
		int finish(void);
};

#endif /* PXPROBE_POPEN_COMMAND_EXECUTOR_H */
