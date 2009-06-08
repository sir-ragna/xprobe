#ifndef PXPROBE_ASYNC_OUTPUT_READER_H
#define PXPROBE_ASYNC_OUTPUT_READER_H

#include "targets_list.h"
#include "CommandExecutor.h"
#include "OutputProcessor.h"

/*
 * will maitaing N concurrent descriptors (returned by CommandExecutor
 * and perform select() on them collecting output and then passing it
 * to the registerd output processors
 */
class AsyncOutputReader {
	private:
		vector<OutputProcessor *> outputProcessors;
		int executeNewCommand(Target *, CommandExecutor *, string);
		int addFD(int, fd_set *, int *);
		void dispatchOutput(string);
	public:
		AsyncOutputReader() { }
		int run(Targets_List &, vector<CommandExecutor *> &, string cmd);
		int registerProcessor(OutputProcessor *);

};
#endif /* PXPROBE_ASYNC_OUTPUT_READER_H */
