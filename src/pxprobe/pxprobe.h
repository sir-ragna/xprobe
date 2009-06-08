#include "CommandExecutor.h"
#include "PopenCommandExecutor.h"
#include "OutputProcessor.h"
#include "PxprobeOutputProcessor.h"
#include "AsyncOutputReader.h"

#define PXPROBE_VERSION "0.1-beta"
#define PXPROBE_BANNER \
"pXprobe [parallel Xprobe] v."PXPROBE_VERSION\
" Copyright (c) 2006 fyodor@o0o.nu, ofir@sys-security.com, meder@o0o.nu"\
"\n"

#define DEFAULT_COMMAND "xprobe2 -B"
