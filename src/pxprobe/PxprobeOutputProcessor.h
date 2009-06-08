#ifndef PXPROBE_PXPROBE_OUTPUT_PROCESSOR_H
#define PXPROBE_PXPROBE_OUTPUT_PROCESSOR_H

#include "pxprobe.h"
#include "xprobe.h"

using namespace std;

class PxprobeOutputProcessor: public OutputProcessor {
	private:
	public:
		int processOutput(string &output);
};

#endif /* PXPROBE_PXPROBE_OUTPUT_PROCESSOR_H */
