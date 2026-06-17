#include <Include/Shared/Hook.h>
#include <Include/Shared/Memory.h>

bool CHookMgr::Init()
{
	return MH_Initialize() == MH_OK;
}

bool CHookMgr::Create(void* target, void* detour, void* original)
{
	return MH_CreateHook(target, detour, (LPVOID*)original) == MH_OK;
}

bool CHookMgr::Create(Module mod, const char* pattern, void* detour, void* original)
{
	void* target = Memory.FindPattern<void*>(mod, pattern);
	if(target)
		return MH_CreateHook(target, detour, (LPVOID*)original) == MH_OK;

	return false;
}

bool CHookMgr::Shutdown()
{
	return MH_Uninitialize() == MH_OK;
}

bool CHookMgr::EnableHooks()
{
	return MH_EnableHook(MH_ALL_HOOKS) == MH_OK;
}

bool CHookMgr::DisableHooks()
{
	return MH_DisableHook(MH_ALL_HOOKS) == MH_OK;
}

CHookMgr Hook;

bool CVMTHook::Init(void* inst)
{
	m_vmt = *reinterpret_cast<void**>(inst);
	return m_vmt != nullptr;
}

bool CVMTHook::Init(Module mod, const char* vtable)
{
	m_vmt = Memory.GetVTable(mod, vtable);
	return m_vmt != nullptr;
}

bool CVMTHook::Hook(int idx, void* fn, void* o)
{
	return MH_CreateHook(reinterpret_cast<void**>(m_vmt)[idx], fn, (LPVOID*)o) == MH_OK;
}

bool CVMTHook::Unhook(int idx)
{
	return MH_RemoveHook(reinterpret_cast<void**>(m_vmt)[idx]) == MH_OK;
}