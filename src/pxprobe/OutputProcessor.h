#ifndef XPROBE_OUTPUT_PROCESSOR_H
#define XPROBE_OUTPUT_PROCESSOR_H

/*
 * abstract class that represents processors of xprobe2 output
 */
#include "xprobe.h"

using namespace std;

class OutputProcessor {

	public:
		virtual int processOutput(string &) =0;
		virtual ~OutputProcessor() {}
};
#endif /*XPROBE_OUTPUT_PROCESSOR_H*/
