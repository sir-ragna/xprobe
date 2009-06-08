#include "PxprobeOutputProcessor.h"
#include "interface.h"
#include "interface_con.h"

extern Interface *ui;

int PxprobeOutputProcessor::processOutput(string &output) {
	
	ui->msg("---[ Instance finished scanning ]--\n%s\n", output.c_str());
	return OK;
}
