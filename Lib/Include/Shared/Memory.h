#ifndef MEMORY_UTIL_H
#define MEMORY_UTIL_H

#include <cstdint>
#include <Windows.h>
#include <vector>

#ifndef PLATFORM_64BITS
#if defined(__x86_64__) || defined(_WIN64)
#define PLATFORM_64BITS 1
#endif
#endif

typedef bool(* ModuleSectionIterator)(PIMAGE_SECTION_HEADER header);

class Module
{
public:
	union
	{
		HMODULE Handle;
		uintptr_t BaseAddress;
		PIMAGE_DOS_HEADER DosHeader;
	};

	inline Module() : BaseAddress(0x0) {}
	inline Module(HMODULE handle) : Handle(handle) {}
	inline Module(const char* name) : Handle(GetModuleHandleA(name)) { }
private:
	PIMAGE_SECTION_HEADER GetFirstSection() const;

public:

	PIMAGE_NT_HEADERS GetNTHeaders() const;
	PIMAGE_SECTION_HEADER GetSection(const char* section) const;
	bool IterateSections(ModuleSectionIterator iterator) const;

	operator HMODULE() const;

	template<typename T>
	inline T GetExport(const char* symbol) const
	{
		return (T)GetProcAddress(Handle, symbol);
	}
};

inline PIMAGE_NT_HEADERS Module::GetNTHeaders() const
{
	if (!BaseAddress)
		return nullptr;

	return reinterpret_cast<PIMAGE_NT_HEADERS>(BaseAddress + DosHeader->e_lfanew);
}

inline Module::operator HMODULE() const
{
	return Handle;
}

template<typename T = void*>
class Pointer
{
private:
	union
	{
		T* m_ptr;
		uintptr_t m_iptr;
	};

protected:
	inline bool CheckValidity(void) const
	{
		return m_ptr != nullptr;
	}

public:
	inline Pointer(void) : m_ptr(nullptr) {}
	inline Pointer(uintptr_t ptr) : m_ptr(reinterpret_cast<T*>(ptr)) {}
	inline Pointer(void* ptr) : m_ptr((T*)ptr) {}

	Pointer<T> Add(uintptr_t off) const;
	Pointer<T> Sub(uintptr_t off) const;
	Pointer<T> Deref() const;

	Pointer<T> operator+(uintptr_t off) const;
	Pointer<T> operator-(uintptr_t off) const;
	void operator+=(uintptr_t off);
	void operator-=(uintptr_t off);
	operator bool() const;

	template<typename _T>
	inline _T Get(void)
	{
		return (_T)m_iptr;
	}

	inline uintptr_t Get(void) const
	{
		return m_iptr;
	}
};

#ifndef MEMORY_UNSAFE_POINTERS
#define CHECK_VALID(p) if(!p->CheckValidity()) return Pointer<T>()
#else
#define CHECK_VALID(p)
#endif

template<typename T>
inline Pointer<T> Pointer<T>::Add(uintptr_t off) const
{
	CHECK_VALID(this);

	return Pointer<T>(m_iptr + off);
}

template<typename T>
inline Pointer<T> Pointer<T>::Sub(uintptr_t off) const
{
	CHECK_VALID(this);

	return Pointer<T>(m_iptr - off);
}

template<typename T>
inline Pointer<T> Pointer<T>::Deref() const
{
	CHECK_VALID(this);

	return Pointer<T>(*((uintptr_t*)m_ptr));
}

template<typename T>
inline Pointer<T> Pointer<T>::operator+(uintptr_t off) const
{
	return Add(off);
}

template<typename T>
inline Pointer<T> Pointer<T>::operator-(uintptr_t off) const
{
	return Sub(off);
}

template<typename T>
inline void Pointer<T>::operator+=(uintptr_t off)
{
	if (!this->CheckValidity())
		return;

	m_iptr += off;
}

template<typename T>
inline void Pointer<T>::operator-=(uintptr_t off)
{
	if (!this->CheckValidity())
		return;

	m_iptr -= off;
}

template<typename T>
inline Pointer<T>::operator bool() const
{
	return m_ptr != nullptr;
}

#undef CHECK_VALID

class CMemoryUtil
{
public:
	std::vector<int> GetBytes(const char* pattern);
	uintptr_t FindPattern(uintptr_t start, uintptr_t end, const char* pattern);
	uintptr_t FindPattern(Module mod, const char* pattern);

	template<typename T>
	inline T FindPattern(Module mod, const char* pattern)
	{
		return reinterpret_cast<T>(FindPattern(mod, pattern));
	}

	const char* FindString(Module mod, const char* str, const char* section = ".rdata");
	void* GetVTable(Module mod, const char* classname);
	void* GetVFunc(void* inst, int idx);

	template<typename T>
	inline T GetVFunc(void* inst, int idx)
	{
		return (T)GetVFunc(inst, idx);
	}

	template<typename T>
	inline T Rip(uintptr_t p)
	{
		return reinterpret_cast<T>(p + *reinterpret_cast<int*>(p) + 4);
	}

	template<typename T>
	inline T Rip(void* p)
	{
		return reinterpret_cast<T>(reinterpret_cast<uintptr_t>(p) + *((int*)p) + 4);
	}

	template<typename T = void*, typename... Patterns>
	inline T FindPatternAny(Module mod, Patterns... patterns)
	{
		T result = T();
		((result = result ? result : FindPattern<T>(mod, patterns)), ...);
		return result;
	}
};

extern CMemoryUtil Memory;

#endif