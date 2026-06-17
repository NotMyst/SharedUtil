#include <Include/Shared/Memory.h>

PIMAGE_SECTION_HEADER Module::GetFirstSection() const
{
	if (BaseAddress == 0x0)
		return nullptr;

	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;

	PIMAGE_NT_HEADERS headers = GetNTHeaders();
	if (!headers)
		return nullptr;
	
	if (headers->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;

	return IMAGE_FIRST_SECTION(headers);
}

PIMAGE_SECTION_HEADER Module::GetSection(const char* section) const
{
	PIMAGE_SECTION_HEADER firstHeader = GetFirstSection();
	PIMAGE_NT_HEADERS headers = GetNTHeaders();
	if (!firstHeader)
		return nullptr;

	if (!headers)
		return nullptr;

	if (headers->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;

	for (WORD i = 0; i < headers->FileHeader.NumberOfSections; ++i)
	{
		if (strcmp(reinterpret_cast<char*>(&firstHeader[i].Name), section) == 0)
			return &firstHeader[i];
	}

	return nullptr;
}

bool Module::IterateSections(ModuleSectionIterator iterator) const
{
	PIMAGE_SECTION_HEADER firstHeader = GetFirstSection();
	PIMAGE_NT_HEADERS headers = GetNTHeaders();
	if (!firstHeader)
		return false;

	if (!headers)
		return false;

	if (headers->Signature != IMAGE_NT_SIGNATURE)
		return false;

	for (WORD i = 0; i < headers->FileHeader.NumberOfSections; ++i)
	{
		if (!iterator(&firstHeader[i]))
			return false;
	}

	return true;
}

std::vector<int> CMemoryUtil::GetBytes(const char* pattern)
{
	auto GetInt = [](char c) -> unsigned int
		{
			if (c >= '0' && c <= '9') return c - '0';
			if (c >= 'A' && c <= 'F') return c - 'A' + 10;
			if (c >= 'a' && c <= 'f') return c - 'a' + 10;
			return 0;
		};

	std::vector<int> bytes = {};
	size_t len = strlen(pattern);
	for (unsigned int i = 0; i < len; i++)
	{
		char c = pattern[i];
		if (c == '?')
		{
			bytes.push_back(-1);

			if (pattern[i + 1] == '?')
				i++;
		}
		else if (c != ' ')
		{
			int cur = GetInt(c);
			if (pattern[i + 1] != ' ' && i + 1 != len)
			{
				cur = (cur << 4) | GetInt(pattern[i + 1]);
				i++;
			}

			bytes.push_back(cur);
		}
	}

	return bytes;
}

uintptr_t CMemoryUtil::FindPattern(uintptr_t start, uintptr_t end, const char* idapattern)
{
	std::vector<int> pattern = GetBytes(idapattern);

	uintptr_t n = end - start;
	size_t m = pattern.size();

	uint8_t* bytes = reinterpret_cast<uint8_t*>(start);

	for (uintptr_t i = 0; i <= n - m; i++) {
		uintptr_t j = 0;

		while (j < m && (pattern[j] == -1 || bytes[i + j] == pattern[j]))
			j++;

		if (j == m)
			return start + i;
	}

	return 0x0;
}

uintptr_t CMemoryUtil::FindPattern(Module mod, const char* pattern)
{
	/*PIMAGE_SECTION_HEADER text = mod.GetSection(".text");
	if (!text)
		return 0x0;

	const uintptr_t start = mod.BaseAddress + text->VirtualAddress;
	const uintptr_t end = start + text->Misc.VirtualSize;*/

	PIMAGE_NT_HEADERS headers = mod.GetNTHeaders();

	return FindPattern(mod.BaseAddress + headers->OptionalHeader.BaseOfCode, mod.BaseAddress + headers->OptionalHeader.BaseOfCode + headers->OptionalHeader.SizeOfCode, pattern);
}

const char* CMemoryUtil::FindString(Module mod, const char* str, const char* section)
{
	PIMAGE_SECTION_HEADER rdata = mod.GetSection(section);
	if (!rdata)
		return nullptr;

	const size_t len = strlen(str);

	if (rdata->Misc.VirtualSize < len)
		return nullptr;

	const uintptr_t start = mod.BaseAddress + rdata->VirtualAddress;
	const uintptr_t end = start + rdata->Misc.VirtualSize;

	for (uintptr_t cur = start; cur < end - len; cur++)
	{
		for (size_t i = 0; i < len; i++)
		{
			char const* c = reinterpret_cast<char*>(cur + i);
			if (*c != str[i])
				break;

			if (i == len - 1)
				return reinterpret_cast<char*>(cur);
		}
	}

	return nullptr;
}

typedef struct TypeDescriptor
{
	const void* pVFTable;
	void* spare;
	//char		name[];
} TypeDescriptor;

typedef const struct s_RTTICompleteObjectLocator {
	unsigned long signature;
	unsigned long offset;
	unsigned long cdOffset;
	TypeDescriptor* pTypeDescriptor;
	struct RTTIClassHierarchyDescriptor* pClassDescriptor;
} RTTICompleteObjectLocator;

void* CMemoryUtil::GetVTable(Module mod, const char* classname)
{
#ifdef PLATFORM_64BITS // TODO: Implement 64bit version
	return nullptr;
#else
	int bufLen = strlen(classname) + 7;
	char* mangled = new char[bufLen];
	sprintf_s(mangled, bufLen, ".?AV%s@@", classname);

	const char* descriptorName = FindString(mod, mangled, ".data");

	delete[] mangled;

	PIMAGE_SECTION_HEADER rdata = mod.GetSection(".rdata");
	if (!rdata)
		return nullptr;

	const uintptr_t rdataStart = mod.BaseAddress + rdata->VirtualAddress;
	const uintptr_t rdataEnd = rdataStart + rdata->Misc.VirtualSize;

	TypeDescriptor* desc = reinterpret_cast<TypeDescriptor*>(reinterpret_cast<uintptr_t>(descriptorName) - 0x8);
	for (uintptr_t i = rdataStart; i < rdataEnd - sizeof(void*); i += sizeof(void*))
	{
		RTTICompleteObjectLocator* col = *reinterpret_cast<RTTICompleteObjectLocator**>(i);

		if (!IsBadReadPtr(col, sizeof(RTTICompleteObjectLocator)))
		{
			if (col->pTypeDescriptor == desc)
			{
				for (uintptr_t j = rdataStart; j < rdataEnd - sizeof(void*); j += sizeof(void*))
				{
					const void* ref = *reinterpret_cast<void**>(j);

					if (ref == col)
						return (void*)(j + sizeof(void*));
				}
			}
		}
	}
	
	return nullptr;
#endif // PLATFORM_64BITS
}

void* CMemoryUtil::GetVFunc(void* inst, int idx)
{
	return (*reinterpret_cast<void***>(inst))[idx];
}



CMemoryUtil Memory;