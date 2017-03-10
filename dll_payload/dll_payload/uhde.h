#ifndef _UHDE_H_
#define _UHDE_H_
#include "hde\\hde64.h"

class uhde64{
public:
	unsigned long disasm(const void *);
	hde64s *gethdes();
private:
	hde64s hde64s_tmp;
};
#endif /* _UHDE_H_ */



