#include "switch_wrapper.h"

void userAppInit(void)
{
	twiliInitialize();
	//socketInitializeDefault();
	//nxlinkStdio();
}

void userAppExit(void)
{
	twiliExit();
	//socketExit();
}