// Copyright (c) 2025 The Dilithion Core developers
// Distributed under the MIT software license

#include <util/stacktrace.h>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
    #include <windows.h>
    #include <dbghelp.h>
    #pragma comment(lib, "dbghelp.lib")
#else
    #include <execinfo.h>
    #include <cxxabi.h>
    #include <cstdlib>
#endif

std::vector<std::string> CaptureStackTrace(int skip_frames) {
    std::vector<std::string> frames;
    
#ifdef _WIN32
    // Windows stack trace using DbgHelp API
    void* stack[64];
    unsigned short captured = CaptureStackBackTrace(skip_frames + 1, 64, stack, nullptr);
    
    if (captured == 0) {
        frames.push_back("  (no stack frames captured)");
        return frames;
    }
    
    HANDLE process = GetCurrentProcess();
    bool symInitialized = SymInitialize(process, nullptr, TRUE) != FALSE;
    
    if (symInitialized) {
        SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);
        
        char symbol_buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char)];
        PSYMBOL_INFO symbol = (PSYMBOL_INFO)symbol_buffer;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = MAX_SYM_NAME;
        
        IMAGEHLP_LINE64 line;
        line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
        DWORD displacement;
        
        for (unsigned short i = 0; i < captured; i++) {
            std::ostringstream oss;
            
            if (SymFromAddr(process, (DWORD64)stack[i], nullptr, symbol)) {
                oss << "0x" << std::hex << std::setw(16) << std::setfill('0') 
                    << (DWORD64)stack[i] << " " << symbol->Name;
                
                if (SymGetLineFromAddr64(process, (DWORD64)stack[i], &displacement, &line)) {
                    oss << " (" << line.FileName << ":" << line.LineNumber << ")";
                }
            } else {
                oss << "0x" << std::hex << std::setw(16) << std::setfill('0') 
                    << (DWORD64)stack[i] << " <unknown>";
            }
            
            frames.push_back(oss.str());
        }
        
        SymCleanup(process);
    } else {
        // Fallback: just show addresses if symbol loading fails
        for (unsigned short i = 0; i < captured; i++) {
            std::ostringstream oss;
            oss << "0x" << std::hex << std::setw(16) << std::setfill('0') 
                << (DWORD64)stack[i] << " <symbols unavailable>";
            frames.push_back(oss.str());
        }
    }
#else
    // Linux/Unix stack trace using backtrace()
    void* array[64];
    int size = backtrace(array, 64);
    char** symbols = backtrace_symbols(array, size);
    
    if (symbols != nullptr) {
        for (int i = skip_frames + 1; i < size; i++) {
            frames.push_back(std::string(symbols[i]));
        }
        free(symbols);
    }
#endif
    
    return frames;
}

std::string FormatStackTrace(const std::vector<std::string>& frames) {
    if (frames.empty()) {
        return "  (no stack trace available)";
    }
    
    std::ostringstream oss;
    for (size_t i = 0; i < frames.size(); i++) {
        oss << "  #" << i << " " << frames[i] << "\n";
    }
    return oss.str();
}

std::string GetStackTrace(int skip_frames) {
    auto frames = CaptureStackTrace(skip_frames + 1);
    return FormatStackTrace(frames);
}

