# Cleanup Plan - Multi-Platform Ransomware

## 🗑️ Files to Delete (Obsolete)

### Build Scripts
- [ ] `build_gcc.bat` - Replaced by build_unix.sh
- [ ] `build_simple.bat` - Redundant with build.bat
- [ ] `COMPILATION.md` - Outdated compilation instructions

### Documentation  
- [ ] `README.md` - Replace with README_UNIX.md (rename to README.md)
- [ ] `CMakeLists.txt` - Replace with CMakeLists_unix.txt (rename to CMakeLists.txt)

## 🔄 Files to Consolidate

### Source Code (Merge with #ifdef)
- [ ] Merge `encryption.cpp` + `encryption_unix.cpp` → `encryption.cpp`
- [ ] Merge `file_scanner.cpp` + `file_scanner_unix.cpp` → `file_scanner.cpp`
- [ ] Merge `anti_analysis.cpp` + `anti_analysis_unix.cpp` → `anti_analysis.cpp`
- [ ] Merge `file_utils.cpp` + `file_utils_unix.cpp` → `file_utils.cpp`
- [ ] Merge `logger.cpp` + `logger_unix.cpp` → `logger.cpp`

## 📝 Files to Rename
- [ ] `README_UNIX.md` → `README.md`
- [ ] `CMakeLists_unix.txt` → `CMakeLists.txt`

## ✅ Files to Keep
- [ ] `build.bat` - Windows build script
- [ ] `build_unix.sh` - Unix/Linux build script  
- [ ] `src/main.cpp` - Main multi-platform code
- [ ] `ransomware.exe` - Windows executable
- [ ] `include/` - Header files
- [ ] `resources/` - Resource directory

## 🎯 Final Structure
```
Ransomware/
├── README.md (multi-platform docs)
├── CMakeLists.txt (multi-platform build)
├── build.bat (Windows)
├── build_unix.sh (Unix/Linux)
├── src/
│   ├── main.cpp
│   ├── core/
│   │   ├── encryption.cpp (unified)
│   │   └── file_scanner.cpp (unified)
│   ├── evasion/
│   │   └── anti_analysis.cpp (unified)
│   └── utils/
│       ├── file_utils.cpp (unified)
│       └── logger.cpp (unified)
├── include/
├── resources/
└── ransomware.exe
```

## 📊 Space Savings
- **Before**: ~15 files, ~80KB source
- **After**: ~10 files, ~60KB source  
- **Reduction**: 33% fewer files, 25% less code
