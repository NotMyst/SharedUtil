#ifndef HOOK_H
#define HOOK_H

#include "../../Ext/Include/Minhook.h"
#include "Memory.h"

class CHookMgr
{
public:
	bool Init();
	bool Create(void* fn, void* detour, void* original);
	bool Create(Module mod, const char* pattern, void* detour, void* original);
	bool Shutdown();
	bool EnableHooks();
	bool DisableHooks();
};

extern CHookMgr Hook;

class CVMTHook
{
private:
	void* m_vmt;

public:
	bool Init(void* inst);
	bool Init(Module mod, const char* vtable);
	bool Hook(int idx, void* fn, void* original);
	bool Unhook(int idx);
};



#endif // HOOK_H