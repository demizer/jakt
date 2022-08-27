/*
 * Copyright (c) 2022, Andreas Kling <kling@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <Jakt/NumericLimits.h>
#include <IO/File.h>
#include <errno.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#    ifndef NOMINMAX
#        define NOMINMAX
#    endif
#  include <Windows.h>
#    ifdef Yield
#        undef Yield // rude
#    endif
#  include <fileapi.h>
#  include <direct.h>
#endif

namespace JaktInternal {

File::File()
{
}

File::~File()
{
    fclose(m_stdio_file);
}

ErrorOr<NonnullRefPtr<File>> File::open_for_reading(String path)
{
    auto* stdio_file = fopen(path.c_string(), "rb");
    if (!stdio_file) {
        return Error::from_errno(errno);
    }
    auto file = TRY(adopt_nonnull_ref_or_enomem(new (nothrow) File));
    file->m_stdio_file = stdio_file;
    return file;
}

ErrorOr<NonnullRefPtr<File>> File::open_for_writing(String path)
{
    auto* stdio_file = fopen(path.c_string(), "wb");
    if (!stdio_file) {
        return Error::from_errno(errno);
    }
    auto file = TRY(adopt_nonnull_ref_or_enomem(new (nothrow) File));
    file->m_stdio_file = stdio_file;
    return file;
}

ErrorOr<Array<u8>> File::read_all()
{
    auto entire_file = TRY(Array<u8>::create_empty());

    while (true) {
        u8 buffer[4096];
        auto nread = fread(buffer, 1, sizeof(buffer), m_stdio_file);
        if (nread == 0) {
            if (feof(m_stdio_file)) {
                return entire_file;
            }
            auto error = ferror(m_stdio_file);
            return Error::from_errno(error);
        }
        size_t old_size = entire_file.size();
        TRY(entire_file.add_size(nread));
        memcpy(entire_file.unsafe_data() + old_size, buffer, nread);
    }
}

ErrorOr<size_t> File::read(Array<u8> buffer)
{
    auto nread = fread(buffer.unsafe_data(), 1, buffer.size(), m_stdio_file);
    if (nread == 0) {
        if (feof(m_stdio_file))
            return 0;
        auto error = ferror(m_stdio_file);
        return Error::from_errno(error);
    }
    return nread;
}

ErrorOr<size_t> File::write(Array<u8> data)
{
    auto nwritten = fwrite(data.unsafe_data(), 1, data.size(), m_stdio_file);
    if (nwritten == 0) {
        auto error = ferror(m_stdio_file);
        return Error::from_errno(error);
    }
    return nwritten;
}

#ifdef _WIN32
bool File::exists(String path)
{
    DWORD attributes = GetFileAttributes(path.c_string());

    // FIXME: ErrorOr<bool> and check for "not exist" vs "no perms"
    return attributes != INVALID_FILE_ATTRIBUTES;
}

ErrorOr<String> File::current_directory()
{
    // To determine the required buffer size, set this parameter to NULL and the nBufferLength parameter to 0.
    DWORD expected_size = GetCurrentDirectory(0, nullptr);

    if (expected_size == 0)
        return Error::from_errno(GetLastError());

    // If the buffer that is pointed to by lpBuffer is not large enough, 
    // the return value specifies the required size of the buffer, in characters, including the null-terminating character.

    char* raw_storage = nullptr;
    auto storage = TRY(StringStorage::create_uninitialized(static_cast<size_t>(expected_size - 1), raw_storage));

    auto final_ret = GetCurrentDirectory(expected_size, raw_storage);

    VERIFY(final_ret == storage->length());

    return String(move(storage));
}

ErrorOr<void> File::make_directory(String path)
{
    // Remove MAX_PATH limit by going full wchar
    // Buckle up

    if (path.length() > NumericLimits<int>::max())
        return Error::from_errno(ENAMETOOLONG);

    path = TRY(path.replace("/", "\\"));

    int expected_size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.c_string(), static_cast<int>(path.length()), nullptr, 0);
    if (expected_size <= 0)
        return Error::from_errno(GetLastError());

    WCHAR unc_prefix[] = L"\\\\?\\";
    size_t actual_size = static_cast<size_t>(expected_size) + wcslen(unc_prefix);
    WCHAR* wide_buffer = ::new (nothrow) WCHAR[actual_size + 1] {};
    if (wide_buffer == nullptr)
        return Error::from_errno(ENOMEM);
    ScopeGuard buffer_cleanup = [wide_buffer] { delete[] wide_buffer; };
    wcscpy(wide_buffer, unc_prefix);

    int ret = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.c_string(), static_cast<int>(path.length() + 1), &wide_buffer[wcslen(unc_prefix)], expected_size + 1);
    if (ret <= 0)
        return Error::from_errno(GetLastError());

    BOOL created = CreateDirectoryW(wide_buffer, nullptr);
    if (created != TRUE)
        return Error::from_errno(GetLastError());

    return {};
}
#else
bool File::exists(String path)
{
    bool can_access = ::access(path.c_string(), F_OK) == 0;

    // FIXME: ErrorOr<bool> and check for "not exist" vs "no perms"
    return can_access;
}

ErrorOr<String> File::current_directory()
{
    char buf[PATH_MAX] = {};

    if (getcwd(buf, PATH_MAX) == nullptr)
        return Error::from_errno(errno);

    return String(TRY(StringStorage::create(buf, strlen(buf))));
}

ErrorOr<void> File::make_directory(String path)
{
    if (::mkdir(path.c_string(), 0644) == 0)
        return {};
    return Error::from_errno(errno);
}
#endif
}
