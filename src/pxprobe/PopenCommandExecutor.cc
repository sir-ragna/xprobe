#include "pxprobe.h"
#include "interface.h"
#include "interface_con.h"

extern Interface *ui;

int PopenCommandExecutor::execute(string &command) {

	r_pipe = popen(command.c_str(), "r");
	if (r_pipe == NULL) {
		ui->error("pxprobe: PopenCommandExecutor::execute(): popen failed: %s\n", strerror(errno));
		return FAIL;
	}
	setDescriptor(fileno(r_pipe));
	return getDescriptor();
}

int PopenCommandExecutor::finish(void) {

	pclose(r_pipe);
	r_pipe = NULL;
	setDescriptor(0);
	return OK;
}
