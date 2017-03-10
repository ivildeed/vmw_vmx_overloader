#include "stdafx.h"
#include "uhde.h"

unsigned long uhde64::disasm(const void *code)
{
	return  hde64_disasm(code,&hde64s_tmp);
}

hde64s *uhde64::gethdes()
{
	return &hde64s_tmp;
}