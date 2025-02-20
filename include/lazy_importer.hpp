/*
 * Copyright 2018-2022 Justas Masiulis - 2024-2025 Ricardo Carvalho
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// === FAQ === documentation is available at https://github.com/JustasMasiulis/lazy_importer
// * Code doesn't compile with errors about pointer conversion:
//  - Try using `nullptr` instead of `NULL` or call `get()` instead of using the overloaded operator()
// * Lazy importer can't find the function I want:
//   - Double check that the module in which it's located in is actually loaded
//   - Try #define LAZY_IMPORTER_CASE_INSENSITIVE
//     This will start using case insensitive comparison globally
//   - Try #define LAZY_IMPORTER_RESOLVE_FORWARDED_EXPORTS
//     This will enable forwarded export resolution globally instead of needing explicit `forwarded()` calls

#ifndef LAZY_IMPORTER_HPP
#define LAZY_IMPORTER_HPP

#define LI_FN(name) ::li::detail::lazy_function<LAZY_IMPORTER_KHASH(#name), decltype(&name)>()
#define LI_PTR(name) (*LI_FN(name).nt_safe())

#define LI_FN_DEF(name) ::li::detail::lazy_function<LAZY_IMPORTER_KHASH(#name), name>()

#define LI_MODULE(name) ::li::detail::lazy_module<LAZY_IMPORTER_KHASH(name)>()

#ifndef LAZY_IMPORTER_CPP_FORWARD
#ifdef LAZY_IMPORTER_NO_CPP_FORWARD
#define LAZY_IMPORTER_CPP_FORWARD(t, v) v
#else
#include <utility>
#define LAZY_IMPORTER_CPP_FORWARD(t, v) std::forward<t>(v)
#endif
#endif

#include <intrin.h>
#include <cstring>

#ifndef LAZY_IMPORTER_NO_FORCEINLINE
#if defined(_MSC_VER)
#define LAZY_IMPORTER_FORCEINLINE __forceinline
#elif defined(__GNUC__) && __GNUC__ > 3
#define LAZY_IMPORTER_FORCEINLINE inline __attribute__((__always_inline__))
#else
#define LAZY_IMPORTER_FORCEINLINE inline
#endif
#else
#define LAZY_IMPORTER_FORCEINLINE inline
#endif

#ifndef LAZY_IMPORTER_NO_NOINLINE
#if defined(_MSC_VER)
#define LAZY_IMPORTER_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) && __GNUC__ > 3
#define LAZY_IMPORTER_NOINLINE __attribute__((noinline))
#else
#define LAZY_IMPORTER_NOINLINE
#endif
#else
#define LAZY_IMPORTER_NOINLINE
#endif

#ifdef LAZY_IMPORTER_CASE_INSENSITIVE
#define LAZY_IMPORTER_CASE_SENSITIVITY false
#else
#define LAZY_IMPORTER_CASE_SENSITIVITY true
#endif

#define LAZY_IMPORTER_STRINGIZE(x) #x
#define LAZY_IMPORTER_STRINGIZE_EXPAND(x) LAZY_IMPORTER_STRINGIZE(x)

#define LAZY_IMPORTER_KHASH(str)                                                                                       \
    ::li::detail::khash(str, ::li::detail::khash_impl(__TIME__ __DATE__ LAZY_IMPORTER_STRINGIZE_EXPAND(__LINE__)       \
                                                          LAZY_IMPORTER_STRINGIZE_EXPAND(__COUNTER__),                 \
                                                      2166136261))

namespace li
{
namespace detail
{
#if _KERNEL_MODE
namespace misc
{
LAZY_IMPORTER_FORCEINLINE const char *get_kernel_base()
{
    const auto idtbase = *reinterpret_cast<uint64_t *>(__readgsqword(0x18) + 0x38);
    const auto descriptor_0 = *reinterpret_cast<uint64_t *>(idtbase);
    const auto descriptor_1 = *reinterpret_cast<uint64_t *>(idtbase + 8);
    const auto isr_base = ((descriptor_0 >> 32) & 0xFFFF0000) + (descriptor_0 & 0xFFFF) + (descriptor_1 << 32);
    auto align_base = isr_base & 0xFFFFFFFFFFFFF000;

    for (;; align_base -= 0x1000)
    {
        for (auto *search_base = reinterpret_cast<uint8_t *>(align_base);
             search_base < reinterpret_cast<uint8_t *>(align_base) + 0xFF9; search_base++)
        {
            if (search_base[0] == 0x48 && search_base[1] == 0x8D && search_base[2] == 0x1D && search_base[6] == 0xFF)
            {
                const auto relative_offset = *reinterpret_cast<int *>(&search_base[3]);
                const auto address = reinterpret_cast<uint64_t>(search_base + relative_offset + 7);
                if ((address & 0xFFF) == 0)
                {
                    if (*reinterpret_cast<uint16_t *>(address) == 0x5A4D)
                    {
                        return reinterpret_cast<const char *>(address);
                    }
                }
            }
        }
    }
}
} // namespace misc
#endif

namespace win
{
struct LIST_ENTRY_T
{
    const char *Flink;
    const char *Blink;
};

struct UNICODE_STRING_T
{
    unsigned short Length;
    unsigned short MaximumLength;
    wchar_t *Buffer;
};

struct PEB_LDR_DATA_T
{
    unsigned long Length;
    unsigned long Initialized;
    const char *SsHandle;
    LIST_ENTRY_T InLoadOrderModuleList;
};

struct PEB_T
{
    unsigned char Reserved1[2];
    unsigned char BeingDebugged;
    unsigned char Reserved2[1];
    const char *Reserved3[2];
    PEB_LDR_DATA_T *Ldr;
};

#if _KERNEL_MODE
struct LDR_DATA_TABLE_ENTRY_T
{
    struct _LIST_ENTRY InLoadOrderLinks;             // 0x0
    const char *ExceptionTable;                      // 0x10
    ULONG ExceptionTableSize;                        // 0x18
    const char *GpValue;                             // 0x20
    struct _NON_PAGED_DEBUG_INFO *NonPagedDebugInfo; // 0x28
    const char *DllBase;                             // 0x30
    const char *EntryPoint;                          // 0x38
    ULONG SizeOfImage;                               // 0x40
    struct _UNICODE_STRING FullDllName;              // 0x48
    struct _UNICODE_STRING BaseDllName;              // 0x58
    ULONG Flags;                                     // 0x68
    USHORT LoadCount;                                // 0x6c
    union {
        USHORT SignatureLevel : 4; // 0x6e
        USHORT SignatureType : 3;  // 0x6e
        USHORT Frozen : 2;         // 0x6e
        USHORT HotPatch : 1;       // 0x6e
        USHORT Unused : 6;         // 0x6e
        USHORT EntireField;        // 0x6e
    } u1;                          // 0x6e
    const char *SectionPointer;    // 0x70
    ULONG CheckSum;                // 0x78
    ULONG CoverageSectionSize;     // 0x7c
    const char *CoverageSection;   // 0x80
    const char *LoadedImports;     // 0x88
    union {
        const char *Spare;                               // 0x90
        struct _KLDR_DATA_TABLE_ENTRY *NtDataTableEntry; // 0x90
    };
    ULONG SizeOfImageNotRounded; // 0x98
    ULONG TimeDateStamp;         // 0x9c

    LAZY_IMPORTER_FORCEINLINE const LDR_DATA_TABLE_ENTRY_T *load_order_next() const noexcept
    {
        return reinterpret_cast<const LDR_DATA_TABLE_ENTRY_T *>(InLoadOrderLinks.Flink);
    }
};
#else
struct LDR_DATA_TABLE_ENTRY_T
{
    LIST_ENTRY_T InLoadOrderLinks;
    LIST_ENTRY_T InMemoryOrderLinks;
    LIST_ENTRY_T InInitializationOrderLinks;
    const char *DllBase;
    const char *EntryPoint;
    union {
        unsigned long SizeOfImage;
        const char *_dummy;
    };
    UNICODE_STRING_T FullDllName;
    UNICODE_STRING_T BaseDllName;

    LAZY_IMPORTER_FORCEINLINE const LDR_DATA_TABLE_ENTRY_T *load_order_next() const noexcept
    {
        return reinterpret_cast<const LDR_DATA_TABLE_ENTRY_T *>(InLoadOrderLinks.Flink);
    }
};
#endif

struct IMAGE_DOS_HEADER
{                              // DOS .EXE header
    unsigned short e_magic;    // Magic number
    unsigned short e_cblp;     // Bytes on last page of file
    unsigned short e_cp;       // Pages in file
    unsigned short e_crlc;     // Relocations
    unsigned short e_cparhdr;  // Size of header in paragraphs
    unsigned short e_minalloc; // Minimum extra paragraphs needed
    unsigned short e_maxalloc; // Maximum extra paragraphs needed
    unsigned short e_ss;       // Initial (relative) SS value
    unsigned short e_sp;       // Initial SP value
    unsigned short e_csum;     // Checksum
    unsigned short e_ip;       // Initial IP value
    unsigned short e_cs;       // Initial (relative) CS value
    unsigned short e_lfarlc;   // File address of relocation table
    unsigned short e_ovno;     // Overlay number
    unsigned short e_res[4];   // Reserved words
    unsigned short e_oemid;    // OEM identifier (for e_oeminfo)
    unsigned short e_oeminfo;  // OEM information; e_oemid specific
    unsigned short e_res2[10]; // Reserved words
    long e_lfanew;             // File address of new exe header
};

struct IMAGE_FILE_HEADER
{
    unsigned short Machine;
    unsigned short NumberOfSections;
    unsigned long TimeDateStamp;
    unsigned long PointerToSymbolTable;
    unsigned long NumberOfSymbols;
    unsigned short SizeOfOptionalHeader;
    unsigned short Characteristics;
};

struct IMAGE_EXPORT_DIRECTORY
{
    unsigned long Characteristics;
    unsigned long TimeDateStamp;
    unsigned short MajorVersion;
    unsigned short MinorVersion;
    unsigned long Name;
    unsigned long Base;
    unsigned long NumberOfFunctions;
    unsigned long NumberOfNames;
    unsigned long AddressOfFunctions;    // RVA from base of image
    unsigned long AddressOfNames;        // RVA from base of image
    unsigned long AddressOfNameOrdinals; // RVA from base of image
};

struct IMAGE_DATA_DIRECTORY
{
    unsigned long VirtualAddress;
    unsigned long Size;
};

struct IMAGE_OPTIONAL_HEADER64
{
    unsigned short Magic;
    unsigned char MajorLinkerVersion;
    unsigned char MinorLinkerVersion;
    unsigned long SizeOfCode;
    unsigned long SizeOfInitializedData;
    unsigned long SizeOfUninitializedData;
    unsigned long AddressOfEntryPoint;
    unsigned long BaseOfCode;
    unsigned long long ImageBase;
    unsigned long SectionAlignment;
    unsigned long FileAlignment;
    unsigned short MajorOperatingSystemVersion;
    unsigned short MinorOperatingSystemVersion;
    unsigned short MajorImageVersion;
    unsigned short MinorImageVersion;
    unsigned short MajorSubsystemVersion;
    unsigned short MinorSubsystemVersion;
    unsigned long Win32VersionValue;
    unsigned long SizeOfImage;
    unsigned long SizeOfHeaders;
    unsigned long CheckSum;
    unsigned short Subsystem;
    unsigned short DllCharacteristics;
    unsigned long long SizeOfStackReserve;
    unsigned long long SizeOfStackCommit;
    unsigned long long SizeOfHeapReserve;
    unsigned long long SizeOfHeapCommit;
    unsigned long LoaderFlags;
    unsigned long NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_OPTIONAL_HEADER32
{
    unsigned short Magic;
    unsigned char MajorLinkerVersion;
    unsigned char MinorLinkerVersion;
    unsigned long SizeOfCode;
    unsigned long SizeOfInitializedData;
    unsigned long SizeOfUninitializedData;
    unsigned long AddressOfEntryPoint;
    unsigned long BaseOfCode;
    unsigned long BaseOfData;
    unsigned long ImageBase;
    unsigned long SectionAlignment;
    unsigned long FileAlignment;
    unsigned short MajorOperatingSystemVersion;
    unsigned short MinorOperatingSystemVersion;
    unsigned short MajorImageVersion;
    unsigned short MinorImageVersion;
    unsigned short MajorSubsystemVersion;
    unsigned short MinorSubsystemVersion;
    unsigned long Win32VersionValue;
    unsigned long SizeOfImage;
    unsigned long SizeOfHeaders;
    unsigned long CheckSum;
    unsigned short Subsystem;
    unsigned short DllCharacteristics;
    unsigned long SizeOfStackReserve;
    unsigned long SizeOfStackCommit;
    unsigned long SizeOfHeapReserve;
    unsigned long SizeOfHeapCommit;
    unsigned long LoaderFlags;
    unsigned long NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_NT_HEADERS
{
    unsigned long Signature;
    IMAGE_FILE_HEADER FileHeader;
#ifdef _WIN64
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
#else
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
#endif
};

struct IMAGE_SECTION_HEADER
{
    unsigned char Name[8];
    union {
        unsigned long PhysicalAddress;
        unsigned long VirtualSize;
    } Misc;
    unsigned long VirtualAddress;
    unsigned long SizeOfRawData;
    unsigned long PointerToRawData;
    unsigned long PointerToRelocations;
    unsigned long PointerToLinenumbers;
    unsigned short NumberOfRelocations;
    unsigned short NumberOfLinenumbers;
    unsigned long Characteristics;
};

} // namespace win

struct forwarded_hashes
{
    unsigned module_hash;
    unsigned function_hash;
};

// 64 bit integer where 32 bits are used for the hash offset
// and remaining 32 bits are used for the hash computed using it
using offset_hash_pair = unsigned long long;

LAZY_IMPORTER_FORCEINLINE constexpr unsigned get_hash(offset_hash_pair pair) noexcept
{
    return (pair & 0xFFFFFFFF);
}

LAZY_IMPORTER_FORCEINLINE constexpr unsigned get_offset(offset_hash_pair pair) noexcept
{
    return static_cast<unsigned>(pair >> 32);
}

template <bool CaseSensitive = LAZY_IMPORTER_CASE_SENSITIVITY>
LAZY_IMPORTER_FORCEINLINE constexpr unsigned hash_single(unsigned value, char c) noexcept
{
    return (value ^ static_cast<unsigned>((!CaseSensitive && c >= 'A' && c <= 'Z') ? (c | (1 << 5)) : c)) * 16777619;
}

LAZY_IMPORTER_FORCEINLINE constexpr unsigned khash_impl(const char *str, unsigned value) noexcept
{
    return (*str ? khash_impl(str + 1, hash_single(value, *str)) : value);
}

LAZY_IMPORTER_FORCEINLINE constexpr offset_hash_pair khash(const char *str, unsigned offset) noexcept
{
    return ((offset_hash_pair{offset} << 32) | khash_impl(str, offset));
}

template <class CharT = char> LAZY_IMPORTER_FORCEINLINE unsigned hash(const CharT *str, unsigned offset) noexcept
{
    unsigned value = offset;

    for (;;)
    {
        char c = *str++;
        if (!c)
            return value;
        value = hash_single(value, c);
    }
}

LAZY_IMPORTER_FORCEINLINE unsigned hash(const win::UNICODE_STRING_T &str, unsigned offset) noexcept
{
    auto first = str.Buffer;
    const auto last = first + (str.Length / sizeof(wchar_t));
    auto value = offset;
    for (; first != last; ++first)
        value = hash_single(value, static_cast<char>(*first));

    return value;
}

LAZY_IMPORTER_FORCEINLINE forwarded_hashes hash_forwarded(const char *str, unsigned offset) noexcept
{
    forwarded_hashes res{offset, offset};

    for (; *str != '.'; ++str)
        res.module_hash = hash_single<true>(res.module_hash, *str);

    ++str;

    for (; *str; ++str)
        res.function_hash = hash_single(res.function_hash, *str);

    return res;
}

LAZY_IMPORTER_FORCEINLINE const win::IMAGE_NT_HEADERS *nt_headers(const char *base) noexcept
{
    return reinterpret_cast<const win::IMAGE_NT_HEADERS *>(
        base + reinterpret_cast<const win::IMAGE_DOS_HEADER *>(base)->e_lfanew);
}

LAZY_IMPORTER_FORCEINLINE const win::IMAGE_EXPORT_DIRECTORY *image_export_dir(const char *base) noexcept
{
    return reinterpret_cast<const win::IMAGE_EXPORT_DIRECTORY *>(
        base + nt_headers(base)->OptionalHeader.DataDirectory->VirtualAddress);
}

struct exports_directory
{
    unsigned long _ied_size;
    const char *_base;
    const win::IMAGE_EXPORT_DIRECTORY *_ied;

  public:
    using size_type = unsigned long;

    LAZY_IMPORTER_FORCEINLINE
    exports_directory(const char *base) noexcept : _base(base)
    {
        const auto ied_data_dir = nt_headers(base)->OptionalHeader.DataDirectory[0];
        _ied = reinterpret_cast<const win::IMAGE_EXPORT_DIRECTORY *>(base + ied_data_dir.VirtualAddress);
        _ied_size = ied_data_dir.Size;
    }

    LAZY_IMPORTER_FORCEINLINE explicit operator bool() const noexcept
    {
        return reinterpret_cast<const char *>(_ied) != _base;
    }

    LAZY_IMPORTER_FORCEINLINE size_type size() const noexcept
    {
        return _ied->NumberOfNames;
    }

    LAZY_IMPORTER_FORCEINLINE const char *base() const noexcept
    {
        return _base;
    }
    LAZY_IMPORTER_FORCEINLINE const win::IMAGE_EXPORT_DIRECTORY *ied() const noexcept
    {
        return _ied;
    }

    LAZY_IMPORTER_FORCEINLINE const char *name(size_type index) const noexcept
    {
        return _base + reinterpret_cast<const unsigned long *>(_base + _ied->AddressOfNames)[index];
    }

    LAZY_IMPORTER_FORCEINLINE const char *address(size_type index) const noexcept
    {
        const auto *const rva_table = reinterpret_cast<const unsigned long *>(_base + _ied->AddressOfFunctions);

        const auto *const ord_table = reinterpret_cast<const unsigned short *>(_base + _ied->AddressOfNameOrdinals);

        return _base + rva_table[ord_table[index]];
    }

    LAZY_IMPORTER_FORCEINLINE bool is_forwarded(const char *export_address) const noexcept
    {
        const auto ui_ied = reinterpret_cast<const char *>(_ied);
        return (export_address > ui_ied && export_address < ui_ied + _ied_size);
    }
};

#if !_KERNEL_MODE
// some helper functions
LAZY_IMPORTER_FORCEINLINE const win::PEB_T *peb() noexcept
{
#if defined(_M_X64) || defined(__amd64__)
#if defined(_MSC_VER)
    return reinterpret_cast<const win::PEB_T *>(__readgsqword(0x60));
#else
    const win::PEB_T *ptr;
    __asm__ __volatile__("mov %%gs:0x60, %0" : "=r"(ptr));
    return ptr;
#endif
#elif defined(_M_IX86) || defined(__i386__)
#if defined(_MSC_VER)
    return reinterpret_cast<const win::PEB_T *>(__readfsdword(0x30));
#else
    const win::PEB_T *ptr;
    __asm__ __volatile__("mov %%fs:0x30, %0" : "=r"(ptr));
    return ptr;
#endif
#elif defined(_M_ARM) || defined(__arm__)
    return *reinterpret_cast<const win::PEB_T **>(_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30);
#elif defined(_M_ARM64) || defined(__aarch64__)
    return *reinterpret_cast<const win::PEB_T **>(__getReg(18) + 0x60);
#elif defined(_M_IA64) || defined(__ia64__)
    return *reinterpret_cast<const win::PEB_T **>(static_cast<char *>(_rdteb()) + 0x60);
#else
#error Unsupported platform. Open an issue and Ill probably add support.
#endif
}

LAZY_IMPORTER_FORCEINLINE const win::PEB_LDR_DATA_T *ldr()
{
    return reinterpret_cast<const win::PEB_LDR_DATA_T *>(peb()->Ldr);
}
#else
static const win::LIST_ENTRY_T *get_ps_loaded_module_list()
{
    static win::LIST_ENTRY_T *ps_loaded_module_list = nullptr;
    if (!ps_loaded_module_list)
    {
        constexpr offset_hash_pair export_hash = LAZY_IMPORTER_KHASH("PsLoadedModuleList");
        const exports_directory exports(misc::get_kernel_base());

        if (exports)
        {
            auto export_index = exports.size();
            while (export_index--)
            {
                if (hash(exports.name(export_index), get_offset(export_hash)) == get_hash(export_hash))
                {
                    ps_loaded_module_list = (win::LIST_ENTRY_T *)(exports.address(export_index));
                    break;
                }
            }
        }
    }
    return ps_loaded_module_list;
}
#endif

LAZY_IMPORTER_FORCEINLINE const win::LDR_DATA_TABLE_ENTRY_T *ldr_data_entry() noexcept
{
#if _KERNEL_MODE
    return reinterpret_cast<const win::LDR_DATA_TABLE_ENTRY_T *>(get_ps_loaded_module_list()->Flink);
#else
    return reinterpret_cast<const win::LDR_DATA_TABLE_ENTRY_T *>(ldr()->InLoadOrderModuleList.Flink);
#endif
}

struct safe_module_enumerator
{
    using value_type = const detail::win::LDR_DATA_TABLE_ENTRY_T;
    value_type *value;
    value_type *head;

    LAZY_IMPORTER_FORCEINLINE safe_module_enumerator() noexcept : safe_module_enumerator(ldr_data_entry())
    {
    }

    LAZY_IMPORTER_FORCEINLINE
    safe_module_enumerator(const detail::win::LDR_DATA_TABLE_ENTRY_T *ldr) noexcept
        : value(ldr->load_order_next()), head(value)
    {
    }

    LAZY_IMPORTER_FORCEINLINE void reset() noexcept
    {
        value = head->load_order_next();
    }

    LAZY_IMPORTER_FORCEINLINE bool next() noexcept
    {
        value = value->load_order_next();

        return value != head && value->DllBase;
    }
};

struct unsafe_module_enumerator
{
    using value_type = const detail::win::LDR_DATA_TABLE_ENTRY_T *;
    value_type value;

    LAZY_IMPORTER_FORCEINLINE unsafe_module_enumerator() noexcept : value(ldr_data_entry())
    {
    }

    LAZY_IMPORTER_FORCEINLINE void reset() noexcept
    {
        value = ldr_data_entry();
    }

    LAZY_IMPORTER_FORCEINLINE bool next() noexcept
    {
        value = value->load_order_next();
        return true;
    }
};

template <typename T = void *, typename A = void *, offset_hash_pair Key> __forceinline T encode_pointer(A ptr)
{
#if LAZY_IMPORTER_ENCODE_POINTER
    struct CryptData
    {
        uint64_t key;
    };

    CryptData key{Key};

    volatile int64_t ptr_data;
    volatile int64_t vkey;

    _InterlockedExchange64(&vkey, (int64_t)(key.key));
    _InterlockedExchange64(&ptr_data, (int64_t)(ptr));

    ptr_data ^= vkey;

    return (T)ptr_data;
#else
    return (T)ptr;
#endif
}

// provides the cached functions which use Derive classes methods
template <offset_hash_pair OHP, class Derived, class DefaultType = void *> class lazy_base
{
  protected:
    static constexpr auto encode_key = OHP ^ 6969L;

    // This function is needed because every templated function
    // with different args has its own static buffer
    LAZY_IMPORTER_FORCEINLINE static void *&_cache() noexcept
    {
        static void *value = nullptr;
        return value;
    }

  public:
    template <class T = DefaultType> LAZY_IMPORTER_FORCEINLINE static T safe() noexcept
    {
        return Derived::template get<T, safe_module_enumerator>();
    }

    template <class T = DefaultType, class Enum = unsafe_module_enumerator>
    LAZY_IMPORTER_FORCEINLINE static T cached() noexcept
    {
        auto &cached = _cache();
        if (!cached)
        {
            cached = encode_pointer<void *, void *, encode_key>(Derived::template get<void *, Enum>());
        }

        return encode_pointer<T, void *, encode_key>(cached);
    }

    template <class T = DefaultType> LAZY_IMPORTER_FORCEINLINE static T safe_cached() noexcept
    {
        return cached<T, safe_module_enumerator>();
    }
};

template <offset_hash_pair OHP> struct lazy_module : lazy_base<OHP, lazy_module<OHP>>
{
    using base_type = lazy_base<OHP, lazy_module<OHP>>;

    template <class T = void *, class Enum = unsafe_module_enumerator> LAZY_IMPORTER_FORCEINLINE static T get() noexcept
    {
        Enum e;
        do
        {
            if (hash(e.value->BaseDllName, get_offset(OHP)) == get_hash(OHP))
                return (T)(e.value->DllBase);
        } while (e.next());
        return {};
    }

    template <class T = void *, class Ldr> LAZY_IMPORTER_FORCEINLINE static T in(Ldr ldr) noexcept
    {
        safe_module_enumerator e(reinterpret_cast<const detail::win::LDR_DATA_TABLE_ENTRY_T *>(ldr));
        do
        {
            if (hash(e.value->BaseDllName, get_offset(OHP)) == get_hash(OHP))
                return (T)(e.value->DllBase);
        } while (e.next());
        return {};
    }

    template <class T = void *, class Ldr> LAZY_IMPORTER_FORCEINLINE static T in_cached(Ldr ldr) noexcept
    {
        auto &cached = base_type::_cache();
        if (!cached)
        {
            cached = encode_pointer<void *, void *, base_type::encode_key>(in(ldr));
        }

        return encode_pointer<T, void *, base_type::encode_key>(cached);
    }
};

template <offset_hash_pair OHP, class T> struct lazy_function : lazy_base<OHP, lazy_function<OHP, T>, T>
{
    using base_type = lazy_base<OHP, lazy_function<OHP, T>, T>;

    template <class... Args> LAZY_IMPORTER_FORCEINLINE decltype(auto) operator()(Args &&...args) const
    {
#ifndef LAZY_IMPORTER_CACHE_OPERATOR_PARENS
        return get()(LAZY_IMPORTER_CPP_FORWARD(Args, args)...);
#else
        return this->cached()(LAZY_IMPORTER_CPP_FORWARD(Args, args)...);
#endif
    }

    template <class F = T, class Enum = unsafe_module_enumerator> LAZY_IMPORTER_FORCEINLINE static F get() noexcept
    {
        // for backwards compatability.
        // Before 2.0 it was only possible to resolve forwarded exports when
        // this macro was enabled
#ifdef LAZY_IMPORTER_RESOLVE_FORWARDED_EXPORTS
        return forwarded<F, Enum>();
#else

        Enum e;

        do
        {
#ifdef LAZY_IMPORTER_HARDENED_MODULE_CHECKS
            if (!e.value->DllBase || !e.value->FullDllName.Length)
                continue;
#endif

            const exports_directory exports(e.value->DllBase);

            if (exports)
            {
                auto export_index = exports.size();
                while (export_index--)
                    if (hash(exports.name(export_index), get_offset(OHP)) == get_hash(OHP))
                        return (F)(exports.address(export_index));
            }
        } while (e.next());
        return {};
#endif
    }

    template <class F = T, class Enum = unsafe_module_enumerator>
    LAZY_IMPORTER_FORCEINLINE static F forwarded() noexcept
    {
        detail::win::UNICODE_STRING_T name;
        forwarded_hashes hashes{0, get_hash(OHP)};

        Enum e;
        do
        {
            name = e.value->BaseDllName;

            wchar_t *extension = wcsrchr(name.Buffer, L'.');
            if (extension)
            {
                name.Length = (unsigned short)((extension - name.Buffer) * sizeof(wchar_t));
            }

            if (!hashes.module_hash || hash(name, get_offset(OHP)) == hashes.module_hash)
            {
                const exports_directory exports(e.value->DllBase);

                if (exports)
                {
                    auto export_index = exports.size();
                    while (export_index--)
                    {
                        if (hash(exports.name(export_index), get_offset(OHP)) == hashes.function_hash)
                        {
                            const auto addr = exports.address(export_index);

                            if (exports.is_forwarded(addr))
                            {
                                hashes = hash_forwarded(reinterpret_cast<const char *>(addr), get_offset(OHP));

                                e.reset();
                                break;
                            }
                            return (F)(addr);
                        }
                    }
                }
            }
        } while (e.next());
        return {};
    }

    template <class F = T> LAZY_IMPORTER_FORCEINLINE static F forwarded_safe() noexcept
    {
        return forwarded<F, safe_module_enumerator>();
    }

    template <class F = T, class Enum = unsafe_module_enumerator>
    LAZY_IMPORTER_FORCEINLINE static F forwarded_cached() noexcept
    {
        auto &value = base_type::_cache();
        if (!value)
        {
            value = encode_pointer<void *, void *, base_type::encode_key>(forwarded<void *, Enum>());
        }

        return encode_pointer<F, void *, base_type::encode_key>(value);
    }

    template <class F = T> LAZY_IMPORTER_FORCEINLINE static F forwarded_safe_cached() noexcept
    {
        return forwarded_cached<F, safe_module_enumerator>();
    }

    template <class F = T, bool IsSafe = false, class Module> LAZY_IMPORTER_FORCEINLINE static F in(Module m) noexcept
    {
        if constexpr (IsSafe)
        {
            if (!m)
                return {};
        }

        const exports_directory exports((const char *)(m));
        if constexpr (IsSafe)
        {
            if (!exports)
                return {};
        }

        unsigned long i = 0;
        const auto export_size = exports.size();

        while (i < export_size)
        {
            if (hash(exports.name(i), get_offset(OHP)) == get_hash(OHP))
                return (F)(exports.address(i));

            ++i;
        }

        return {};
    }

    template <class F = T, class Module> LAZY_IMPORTER_FORCEINLINE static F in_safe(Module m) noexcept
    {
        return in<F, true>(m);
    }

    template <class F = T, bool IsSafe = false, class Module>
    LAZY_IMPORTER_FORCEINLINE static F in_cached(Module m) noexcept
    {
        auto &value = base_type::_cache();
        if (!value)
        {
            value = encode_pointer<void *, void *, base_type::encode_key>(in<void *, IsSafe>(m));
        }

        return encode_pointer<F, void *, base_type::encode_key>(value);
    }

    template <class F = T, class Module> LAZY_IMPORTER_FORCEINLINE static F in_safe_cached(Module m) noexcept
    {
        return in_cached<F, true>(m);
    }

    template <class F = T> LAZY_IMPORTER_FORCEINLINE static F nt() noexcept
    {
#if _KERNEL_MODE
        return in<F>(ldr_data_entry()->DllBase);
#else
        return in<F>(ldr_data_entry()->load_order_next()->DllBase);
#endif
    }

    template <class F = T> LAZY_IMPORTER_FORCEINLINE static F nt_safe() noexcept
    {
#if _KERNEL_MODE
        return in_safe<F>(ldr_data_entry()->DllBase);
#else
        return in_safe<F>(ldr_data_entry()->load_order_next()->DllBase);
#endif
    }

    template <class F = T> LAZY_IMPORTER_FORCEINLINE static F nt_cached() noexcept
    {
#if _KERNEL_MODE
        return in_cached<F>(ldr_data_entry()->DllBase);
#else
        return in_cached<F>(ldr_data_entry()->load_order_next()->DllBase);
#endif
    }

    template <class F = T> LAZY_IMPORTER_FORCEINLINE static F nt_safe_cached() noexcept
    {
#if _KERNEL_MODE
        return in_safe_cached<F>(ldr_data_entry()->DllBase);
#else
        return in_safe_cached<F>(ldr_data_entry()->load_order_next()->DllBase);
#endif
    }
};

} // namespace detail
} // namespace li

#endif // include guard
