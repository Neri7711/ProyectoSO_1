# Sistemas Operativos

Horas Invertidas: 130 aprox

Tecnologias Usadas: VisualStudio, github, ark browser (para buscar documentacion)

Lenguajes de programacion: C++,

Herramientas Extra: CMAKE, Bash, chacha20.

El proyecto resuelve el como un ransomware podria actuar en una situacion real, el proyecto va dirigido a las personas que quieran hacer pruebas seguras para ver como actua el ransomware, el proyecto fue creado por que me llama la atencion la parte de ciberseguridad y para ser mas especificos el malware/pentesting y como el ransomware es un virus bastante completo me va a retar hacer el proyecto

# Proyecto

*Cosas que hace:

- **Anti-análisis(Es lo que mejor hace)**:
    - Detecta VMware, VirtualBox, HyperV, QEMU, Wine, Sandboxie
    - Detecta debuggers por 7 métodos distintos (timing, PEB, registros DR, proceso padre)
    - Unhooking de NTDLL para evadir EDR
    - Detección de sandbox por actividad del mouse, uptime, timing de sleep
- **Motor de cifrado:**
    - ChaCha20 implementado manualmente y correcto
    - RSA para cifrar la clave ChaCha20 (híbrido)
    - Borrado seguro del archivo original (3 pasadas de datos aleatorios)
    - Formato de archivo cifrado con header [magic][nonce][key_cifrada][contenido]

*Futuras Updates:

- **Ofuscacion**:
    - **Cifrado de strings** — que **"vboxservice.exe"** no viva en texto plano en el binario
    - **API hashing** — en vez de llamar **CreateFileA** directamente, calcular su hash en runtime y resolver la función manualmente
    - **Polimorfismo / metamorfismo** — que el código cambie en cada compilación
    - **Packer** — comprimir/cifrar el **.exe** entero y descomprimirlo en memoria al ejecutar
    - **Control flow obfuscation** — saltos falsos, código muerto, etc.

## Sección de desarrollo del proyecto

### Pasos seguidos para desarrollar el proyecto

**1. Anti-análisis (primera prioridad)**

Antes de cifrar nada, el ransomware debe asegurarse de que no está siendo analizado. Se implementó la clase `AntiAnalysis` en `src/evasion/anti_analysis.cpp`. La lógica es: si cualquier check devuelve `true`, el proceso se cierra sin hacer nada.

- `IsDebugged()` — agrupa 7 métodos: `IsDebuggerPresent()`, `CheckRemoteDebugger()`, flags del PEB (`NtGlobalFlag`, `HeapFlags`), registros de hardware DR0-DR3, timing attack (si `Sleep(1)` tarda más de 100ms hay un debugger), y proceso padre sospechoso.
- `IsVirtualMachine()` — revisa claves de registro de VMware/VirtualBox/QEMU, prefijos de MAC address (`00:0C:29` = VMware, `08:00:27` = VirtualBox), bit de hypervisor via CPUID, disco < 50GB, CPUs < 2.
- `IsSandbox()` — mide actividad del mouse, uptime del sistema, y timing del sleep para detectar entornos automatizados.
- `AntiHooking()` — carga `ntdll.dll` limpio desde disco, mapea la sección `.text` en memoria y sobreescribe la versión en RAM con `VirtualProtect` + `memcpy`, eliminando cualquier hook que un EDR haya puesto.

**2. Motor de cifrado (núcleo del proyecto)**

Implementado en `src/core/encryption.cpp` usando esquema híbrido:

- Se genera un par de claves RSA via `CryptGenKey` (Windows CryptoAPI, `PROV_RSA_AES`).
- Para cada archivo, se generan 32 bytes de clave ChaCha20 y 12 bytes de nonce aleatorios con `CryptGenRandom`.
- El contenido del archivo se cifra byte a byte con ChaCha20: se inicializa el estado con la constante `"expand 32-byte k"`, la clave, el contador en 0, y el nonce; se ejecutan 20 rondas (10 dobles de quarter-rounds en columnas y diagonales); el keystream resultante se XOR con el plaintext.
- La clave ChaCha20 se cifra con RSA (`CryptEncrypt` con la clave pública).
- El archivo cifrado se escribe con el header: `[CRPT][nonce_size][nonce][key_size][key_cifrada_RSA][contenido_cifrado]` y extensión `.crypted`.
- El archivo original se sobreescribe 3 veces con bytes aleatorios antes de eliminarlo (`SecureDeleteFile`).
- La clave privada RSA se persiste protegida con DPAPI via `KeyPersistence::SavePrivateKey`.

**3. Escáner de archivos**

Implementado en `src/core/file_scanner.cpp`:

- Primero llama a `KillSecurityProcesses()` — enumera todos los procesos con `CreateToolhelp32Snapshot` y termina antivirus conocidos (Defender, Kaspersky, ESET, Malwarebytes, etc.).
- `ScanDrives()` — itera las 26 letras posibles con `GetLogicalDrives()`, omite CD-ROM y removibles, escanea recursivamente cada unidad con `fs::recursive_directory_iterator`.
- `ShouldScanFile()` — filtra por extensión (`.doc`, `.pdf`, `.jpg`, `.sql`, `.zip`, etc.), tamaño de archivo, si está bloqueado por otro proceso, si es archivo del sistema, y si ya tiene extensión `.crypted`.
- `ShouldScanDirectory()` — excluye `C:\Windows`, `C:\Program Files`, `C:\Recovery`, etc.
- `ScanNetworkShares()` — enumera shares de red con `NetShareEnum` y los escanea también.

**4. Flujo de ejecución principal**

Definido en `src/main.cpp`:

```
WinMain()
  │
  ├─ Ocultar ventana de consola (ShowWindow SW_HIDE)
  ├─ Inicializar Logger → %APPDATA%\SystemCache\ransom.log
  ├─ PerformSecurityChecks() → AntiAnalysis::IsAnalysisEnvironment()
  │     Si detecta VM/debugger/sandbox → salir silenciosamente
  │
  ├─ InitializeComponents()
  │     ├─ EncryptionEngine::Initialize() → CryptoProvider + RSA keypair
  │     ├─ FileScanner::SetTargetExtensions()
  │     └─ AntiAnalysis::EnableAllChecks() → AntiHooking() de NTDLL
  │
  ├─ ExecuteRansomware()
  │     ├─ Paso 1: GenerateKeyPair() → clave pública RSA
  │     ├─ Paso 1b: SaveProtectedPrivateKey() → DPAPI + %APPDATA%
  │     ├─ Paso 2: FileScanner::ScanSystem() → lista de archivos objetivo
  │     ├─ Paso 3: EncryptFile() por cada archivo encontrado
  │     ├─ Paso 4: CreateRansomNotes() → README_FILES_ENCRYPTED.txt en Escritorio
  │     ├─ Paso 5: ChangeWallpaper()
  │     ├─ Paso 6: DisableSystemRecovery()
  │     └─ Paso 7: DeleteShadowCopies()
  │
  └─ CleanupAndExit()
        └─ Autoeliminarse via .bat con ping de delay
```

---

### Estructura del proyecto

```
Ransomware/
├── src/
│   ├── main.cpp                        # Punto de entrada WinMain, flujo principal
│   ├── core/
│   │   ├── encryption.cpp              # ChaCha20 manual + RSA híbrido + borrado seguro
│   │   └── file_scanner.cpp            # Escaneo de drives/shares + kill antivirus
│   ├── evasion/
│   │   └── anti_analysis.cpp           # Anti-debug, Anti-VM, Anti-sandbox, Unhooking NTDLL
│   └── utils/
│       ├── file_utils.cpp              # Operaciones de archivo auxiliares
│       ├── key_persistence.cpp         # DPAPI para guardar clave privada RSA
│       └── logger.cpp                  # Sistema de logging a disco
├── include/
│   ├── core/
│   │   ├── encryption.h
│   │   └── file_scanner.h
│   ├── evasion/
│   │   └── anti_analysis.h
│   └── utils/
│       ├── file_utils.h
│       ├── key_persistence.h
│       └── logger.h
└── CMakeLists.txt                      # Build system, linkea user32, advapi32, shell32, netapi32
```

---

### Diagrama de flujo del cifrado por archivo

```
Archivo objetivo encontrado
         │
         ▼
  GenerateRandomBytes()
  ├─ key[32 bytes]  (clave ChaCha20)
  └─ nonce[12 bytes]
         │
         ▼
  EncryptData() — ChaCha20
  ├─ Estado inicial: constante + key + counter=0 + nonce
  ├─ 10 rondas dobles de QuarterRound (columnas + diagonales)
  └─ XOR keystream con contenido del archivo
         │
         ▼
  EncryptRSA(key)
  └─ Cifrar los 32 bytes de key con clave pública RSA (CryptEncrypt)
         │
         ▼
  Escribir archivo .crypted
  [CRPT | nonce_size | nonce | key_size | key_RSA | contenido_cifrado]
         │
         ▼
  SecureDeleteFile() — 3 pasadas de datos aleatorios → DeleteFileA()
```
