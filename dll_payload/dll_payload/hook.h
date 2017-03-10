

#define LODWORD(_qw)    (unsigned long)(_qw)
#define HIDWORD(_qw)    (unsigned long)((_qw)>>32)

#ifdef _WIN64
#define dptr unsigned __int64
#else
#define dptr unsigned __int32
#endif

#ifdef _WIN64
#define hooksize 14 // jmp addr
#else
#define hooksize 5 // jmp addr
#endif

class hook{
public:
	bool sethook(void *,void *, void **);
	void *restore_buffer;
private:
	unsigned long len;
	bool hook_active;
};

