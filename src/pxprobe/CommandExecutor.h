#ifndef PXPROBE_COMMAND_EXECUTOR_H
#define PXPROBE_COMMAND_EXECUTOR_H

#include "xprobe.h"

using namespace std; 

class CommandExecutor {
	private:
		string output;
		int descriptor;
	protected:
		void setDescriptor(int desc) { descriptor = desc; } 
	public:
		CommandExecutor() {}
		virtual ~CommandExecutor() {}
		virtual int execute(string &) =0;
		virtual int finish(void) =0;
		void appendOutput(const char *buf) { output.append(buf); }
		string getOutput(void) { return output; }
		void clearOutput(void) { output.clear(); }
		int getDescriptor(void) { return descriptor; }
		
};

#endif /* PXPROBE_COMMAND_EXECUTOR_H */
