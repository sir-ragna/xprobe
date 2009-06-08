#include "AsyncOutputReader.h"
#include "interface.h"

extern Interface *ui;

int AsyncOutputReader::run(Targets_List &targets, vector<CommandExecutor *> &executors, string cmd) {
	Target *tg;
	fd_set readfds, readfdscopy;
	int descr, maxfd=0, nready, nbeingexecuted=0;
	/*
	 * initialize
	 */
	FD_ZERO(&readfds);
	for (unsigned int ix = 0; ix < executors.size(); ix++) {
		if ((tg = targets.getnext()) != NULL) {
			descr = executeNewCommand(tg, executors[ix], cmd);
			addFD(descr, &readfdscopy, &maxfd);
			nbeingexecuted++;
		}
	}
	tg=NULL;
	/*
	 * main loop
	 */
	while (nbeingexecuted > 0 || tg != NULL || (tg=targets.getnext()) != NULL ) {
		readfds = readfdscopy;
		nready = select(maxfd+1, &readfds, NULL, NULL, NULL);
		if (nready == -1) {
			ui->error("pxprobe: AsyncOutputReader.run(): select() failed: %s\n", strerror(errno));
			return FAIL;
		} else if (nready) {
			for (unsigned int ix = 0; ix < executors.size(); ix++) {
				if (FD_ISSET(executors[ix]->getDescriptor(), &readfds)) {
					char buf[4096];
					bzero(buf, sizeof(buf));
					int bytesread = read(executors[ix]->getDescriptor(), buf, sizeof(buf));
					if (bytesread > 0) {
						executors[ix]->appendOutput(buf);
					} else if (bytesread == 0) {
						/* process execution finished */
						FD_CLR(executors[ix]->getDescriptor(), &readfdscopy);
						executors[ix]->finish();
						/* give the output to interested parties */
						dispatchOutput(executors[ix]->getOutput());
						executors[ix]->clearOutput();
						/* add new target into the slot that got free */
						if (tg != NULL) {
							addFD(executeNewCommand(tg, executors[ix], cmd), &readfdscopy, &maxfd);
							tg = NULL;
						} else if ((tg = targets.getnext()) != NULL) {
							addFD(executeNewCommand(tg, executors[ix], cmd), &readfdscopy, &maxfd);
							tg = NULL;
						} else {
							tg = NULL;
							nbeingexecuted--;
						}
					}
					if (--nready == 0) {
						break;
					}
				}
			}
		} else {
			ui->error("pxprobe: xprobe2 process hung?\n");
			return FAIL;
		}
	}
	return OK;
}

int AsyncOutputReader::registerProcessor(OutputProcessor *processor) {

	if (processor != NULL) {
		outputProcessors.push_back(processor);
	}
	return OK;
}

int AsyncOutputReader::addFD(int descr, fd_set *set, int *max) {
	if (descr < 0) return FAIL;
	if (descr > *max) *max = descr;
	FD_SET(descr, set);
	return OK;
}

void AsyncOutputReader::dispatchOutput(string output) {

	for (unsigned int ix = 0; ix < outputProcessors.size(); ix++) {
		outputProcessors[ix]->processOutput(output);
	}
}

int AsyncOutputReader::executeNewCommand(Target *tg, CommandExecutor *exec, string command) {

	command.append(" ");
	command.append(inet_ntoa(tg->get_addr()));
	return exec->execute(command);
}
