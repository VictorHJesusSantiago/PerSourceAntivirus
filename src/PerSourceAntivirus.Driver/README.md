# PerSourceAntivirus Kernel Minifilter Driver

Driver de modo kernel para varredura on-access de arquivos, com callbacks de processo/imagem e proteção anti-injeção.

## Funcionalidades

- **On-access file scan**: intercepta `IRP_MJ_CREATE` (pré-criação), lê os primeiros 4 KB do arquivo e envia para o serviço usermode via porta de comunicação de filtro (`\PSAVScanPort`). O serviço responde com `SafeToOpen`; em negação o IRP retorna `STATUS_ACCESS_DENIED`.
- **Cache de arquivos limpos**: hash de `FileId` em 1024 buckets para evitar re-escaneamento.
- **Kernel callbacks**:
  - `PsSetCreateProcessNotifyRoutineEx` — notifica criação/término de processos
  - `PsSetLoadImageNotifyRoutine` — notifica carregamento de imagens (DLL/EXE)
  - `ObRegisterCallbacks` — strip de rights de injeção (`PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`, `PROCESS_CREATE_THREAD`) de handles abertos por processos não-PSAV
- Eventos de kernel enviados assincramente ao serviço via segunda porta (`\PSAVEventPort`)

## Pré-requisitos

| Componente | Versão |
|---|---|
| Windows Driver Kit (WDK) | 10.0.26100+ (Windows 11 24H2 SDK) |
| Visual Studio | 2022 com componente "Windows Driver Development" |
| CMake | 3.25+ (opcional, para build via linha de comando) |
| Windows 10/11 (alvo) | x64 |

## Build — Visual Studio (recomendado)

1. Instale o WDK: [https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk](https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk)
2. Abra o Visual Studio 2022 → **File → Open → CMake** → selecione `src/PerSourceAntivirus.Driver/CMakeLists.txt`
3. Selecione configuração `Debug|x64` ou `Release|x64`
4. **Build → Build All** → gera `PerSourceAntivirus.Driver.sys` e `PerSourceAntivirus.Driver.inf`

## Build — linha de comando (CMake + WDK)

```powershell
# No Developer Command Prompt do Visual Studio 2022 com WDK
cd src/PerSourceAntivirus.Driver
cmake -B build -A x64 -DCMAKE_SYSTEM_NAME=WindowsKernelModeDriver10.0
cmake --build build --config Release
```

## Instalação em modo de desenvolvimento (Test Signing)

Para desenvolvimento local sem certificado EV, ative o Test Mode do Windows:

```powershell
# Executar como Administrador — reiniciar depois
bcdedit /set testsigning on
```

Após reiniciar, aparecerá "Test Mode" na área de trabalho.

### Assinar o driver com certificado de teste

```powershell
# Gerar certificado auto-assinado
makecert -r -pe -ss PrivateCertStore -n "CN=PSAVTestCert" PSAVTestCert.cer

# Assinar o .sys
signtool sign /v /s PrivateCertStore /n "PSAVTestCert" /t http://timestamp.digicert.com PerSourceAntivirus.Driver.sys

# Instalar o certificado como Trusted Publisher e Root CA
certutil -addstore "Root" PSAVTestCert.cer
certutil -addstore "TrustedPublisher" PSAVTestCert.cer
```

### Instalar e carregar o driver

```powershell
# Instalar via INF
pnputil /add-driver PerSourceAntivirus.Driver.inf /install

# Ou manualmente via sc
sc create PSAVDriver binPath= "C:\caminho\PerSourceAntivirus.Driver.sys" type= kernel start= demand
sc start PSAVDriver

# Verificar se está carregado
fltmc | findstr PSAV
```

### Desinstalar

```powershell
sc stop PSAVDriver
sc delete PSAVDriver
fltmc unload PSAVDriver
```

## Produção (sem Test Mode)

Para distribuição em produção é obrigatório:

1. **Certificado EV (Extended Validation)** de CA aprovada pela Microsoft (DigiCert, Sectigo, etc.)
2. **WHQL submission** via [Hardware Dev Center](https://partner.microsoft.com/dashboard/hardware) para obter assinatura da Microsoft
3. **ELAM (Early Launch Anti-Malware)** para registro como AV oficial — requer parceria com Microsoft

Sem esses passos, o driver não carrega no Windows 11 (Secure Boot ativo) com Kernel-Mode Code Signing (KMCS) obrigatório.

## Arquitetura de comunicação

```
Serviço usermode (C#)               Kernel (driver .sys)
─────────────────────────────────   ─────────────────────────────────
MinifilterCommunicator.cs           DriverEntry()
  FilterConnectCommunicationPort ←→  FltCreateCommunicationPort(\PSAVScanPort)
  FilterGetMessage               ←   PsavPreCreate → FltSendMessage
  FilterReplyMessage             →   reply: SafeToOpen
                                 
KernelEventCommunicator.cs          
  FilterConnectCommunicationPort ←→  FltCreateCommunicationPort(\PSAVEventPort)
  FilterGetMessage (async)       ←   ProcessNotify/ImageNotify → async send
```

## Depuração

Conecte um depurador de kernel via WinDbg (serial ou rede):

```powershell
# Na VM alvo (habilitar debug)
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.1.100 port:50000

# No host
windbg -k net:port=50000,key=<gerado acima>
```

Símbolos do driver carregados automaticamente se `PerSourceAntivirus.Driver.pdb` estiver ao lado do `.sys`.
