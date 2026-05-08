================================================================================
  LEKCIJA 2: "OPERATIVNA ANONIMNOST" — Teorija Naprednog Stealth Dizajna
================================================================================

"Najbolji alat je onaj kojeg nikada ne primijetite. Najbolji trag je onaj 
kojeg nikada ne ostavite."

================================================================================
  0. METODOLOGIJA: Layered Evasion Architecture (LEA)
================================================================================

Prethodna lekcija pokazala je KAKO AV/EDR sustavi rade. Ova lekcija pokazuje
KAKO dizajnirati kod koji je inherentno nevidljiv tim sustavima.

Core princip: NE raditi jednu veliku stvar dobro, raditi MILIJUN malih stvari
besprijekorno.

  ┌─────────────────────────────────────────────────────────────────────────┐
  │                    LAYER 1: PRESENTATION LAYER                         │
  │           (Što AV/EDR vidi na površini)                                │
  │  - File entropy, import table, string analysis                         │
  │  - Ovdje: Polimorfizam, import minimizacija, string encryption         │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                    LAYER 2: BEHAVIORAL LAYER                           │
  │           (Što proces radi tijekom izvođenja)                          │
  │  - API calls, memory patterns, network signatures                      │
  │  - Ovdje: Indirect syscalls, API hashing, dynamic resolution           │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                    LAYER 3: CONTEXTUAL LAYER                           │
  │           (Kako se proces ponaša u odnosu na ostatak sustava)          │
  │  - Parent-child odnosi, network timing, persistence mehanizmi          │
  │  - Ovdje: Process masquerading, jitter, WMI persistence                │
  ├─────────────────────────────────────────────────────────────────────────┤
  │                    LAYER 4: ENVIRONMENTAL LAYER                        │
  │           (Kako kod reagira na analitičko okruženje)                   │
  │  - VM detection, sandbox evasion, debugger detection                   │
  │  - Ovdje: Hardware-fingerprinting, anti-analysis, delayed execution    │
  └─────────────────────────────────────────────────────────────────────────┘

Svaki layer je sam po sebi slab. Zajedno čine kod koji je praktično 
nevidljiv statičkoj i dinamičkoj analizi.

================================================================================
  1. LAYER 1: PRESENTATION — Nevidljivost u Mirovanju
================================================================================

1.1 FILE ENTROPY MANIPULACIJA
─────────────────────────────
AV sustavi koriste entropy analizu za detekciju šifriranog/upaljakanog koda.
Visoki entropy (>7.0/8.0) = automatski sumnjivo.

Tehnika: **Controlled Entropy Injection**
  - Miješanje stvarnog koda s velikim količinama "dekorativnih" podataka
  - Umetanje legitimanih stringova (Windows API dokumentacija, 
    Microsoft copyright tekstovi) kao "camouflage"
  - Korištenje kompresije umjesto šifriranja gdje je to moguće
  - RC4/XOR koristiti SAMO za kritične stringove, ostaviti 
    "obične" stringove da balansiraju entropy

1.2 IMPORT TABLE MINIMIZACIJA
─────────────────────────────
Velike tablice importa (npr. 50+ funkcija iz ntdll.dll, kernel32.dll) su 
automatizirani IOC.

Tehnika: **Dynamic API Resolution via PEB Walking**
  - U source kodu: NEMA direktnih poziva syscall.NewLazyDLL("ntdll.dll")
  - Runtime: Hitanje po InMemoryOrderModuleList iz PEB-a
  - Funkcije se rezolviraju preko hash vrijednosti imena, ne stringova
  - Rezultat: Import tablica sadrži SAMO standardne funkcije

Pseudokod principa:
  
  func resolveAPI(dllHash, funcHash uint32) uintptr {
      // 1. Pronađi PEB (Process Environment Block)
      peb := getPEB()
      
      // 2. Iteriraj kroz LDR modul liste
      for mod := peb.Ldr.InMemoryOrderModuleList; mod != nil; mod = mod.Next {
          // 3. Hashiraj ime DLL-a
          if hashModuleName(mod.BaseDllName) == dllHash {
              // 4. Walk export tablicu
              exports := getExportTable(mod.DllBase)
              for _, exp := range exports {
                  if hashFunctionName(exp.Name) == funcHash {
                      return mod.DllBase + exp.RVA
                  }
              }
          }
      }
      return 0
  }

1.3 STRING ENCRYPTION — Runtime Decryption
──────────────────────────────────────────
Nijedan kritičan string ne smije postojati u plaintext obliku u binaryju.

Tehnika: **XOR Stream Cipher s Runtime Key Derivation**
  - Ključ nije hardkodiran — derivira se iz environment varijabli
    kombiniranih s hardware fingerprintom
  - Svaki string ima vlastiti "salt" — ključ se mijenja po stringu
  - Dekripcija se događa SAMO u trenutku korištenja
  - Odmah nakon korištenja, memorija se overwrite-a s nulama

Primjer u kodu (viđet ćemo u praktičnom dijelu):
  
  // ENCRYPTED — decrypt se događa u runtime
  sK32 := dStr([]byte{0x4B,0x33,0x72,0x6E,0x33,0x6C,0x33,...}, 
               deriveKey())  // -> "kernel32.dll"
  
  // JEDNOKRATNA upotreba — nakon poziva, buffer se nulira
  ptr := resolveAPI(hash(sK32), hash("CreateFileW"))
  memZero(sK32)  // Odmah uništi plaintext

================================================================================
  2. LAYER 2: BEHAVIORAL — Nevidljivost u Pokretu
================================================================================

2.1 INDIRECT SYSCALLS — Obolijevanje od Hook-ova
─────────────────────────────────────────────────
Moderni EDR sustavi (CrowdStrike, SentinelOne, Microsoft Defender for Endpoint)
hook-aju korisničke-mode API-je u ntdll.dll. Svaki direktni poziv 
NtCreateThreadEx, NtAllocateVirtualMemory, NtWriteVirtualMemory = instant 
detection.

Tehnika: **Direct Syscall Invocation via SSDT Index**
  - Umjesto poziva NTDLL funkcija, syscall izravno pozivamo preko 
    assembly instrukcija: mov eax, [SSDT_INDEX]; syscall
  - SSDT index se dobiva dinamički — čitanje prvih bajtova funkcije 
    iz NOVE kopije ntdll.dll (ne hook-ane)
  - Koristimo Hell's Gate / Halo's Gate tehniku:
    * Učitaj "čistu" ntdll.dll iz \KnownDlls\ i očitaj SSDT index-e

Pseudokod:

  func indirectSyscall(ssdtIndex uint16, args ...uintptr) {
      // Assembly:
      //   mov rcx, arg0    (ili r10 za Windows)
      //   mov rdx, arg1
      //   mov r8,  arg2
      //   mov r9,  arg3
      //   mov rax, ssdtIndex
      //   syscall
      //   ret
  }

2.2 API HASHING — Funkcije bez imena
────────────────────────────────────
EDR sustavi logging-aju sve API pozive po imenu. Ako koristite 
"NtCreateThreadEx" u kodu, to je u logu.

Tehnika: **djb2 Hash za sve API identifikatore**
  - Svaka funkcija se identificira preko 32-bit hash vrijednosti
  - Hash se računa u runtime iz export tablice
  - U kodu postoje SAMO hash vrijednosti — nema imena funkcija

  const (
      hNtAllocateVirtualMemory = 0x8B1E3C7A  // djb2("NtAllocateVirtualMemory")
      hNtWriteVirtualMemory    = 0xF4D2A9E1  // djb2("NtWriteVirtualMemory")
      hNtCreateThreadEx        = 0x7C3E9B2F  // djb2("NtCreateThreadEx")
  )

2.3 PROCESS INJECTION — UMP (Userland Memory Patching)
─────────────────────────────────────────────────────
Klasici kao "CreateRemoteThread" su mrtvi za EDR. Svaka EDR će detektirati.

Tehnika: **APC Injection + Early Bird + NtAlertThread**
  - 1. Target legitiman proces (explorer.exe, svchost.exe)
  - 2. VirtualAllocEx -> WriteProcessMemory (INDIRECT, preko syscall-a)
  - 3. QueueUserAPC sa NtAlertThread za instant izvršavanje
  - 4. Koristiti "Early Bird" — injektirati u child proces ODMAH nakon 
       CreateProcessW (dok je još suspended)

Tehnika: **Process Doppelgänging**
  - Koristi NTFS Transactional file semantics
  - Kreira "rollback" transakciju nad legitimnom datotekom
  - Overwrite-uje sadržaj transakcije shellcode-om
  - Rollback se nikada ne commit-a — file ostaje "čist" na disku
  - CreateProcess iz transakcije = izvršavanje bez tragova

================================================================================
  3. LAYER 3: CONTEXTUAL — Nevidljivost u Sustavu
================================================================================

3.1 PARENT SPOOFING — Lažni identitet
─────────────────────────────────────
EDR sustavi grade "Process Tree" — hijerarhiju tko je koga pokrenuo.
explorer.exe -> cmd.exe -> powershell.exe = suspicious chain

Tehnika: **PPID Spoofing (Parent Process ID Spoofing)**
  - 1. Odaberi legitiman parent proces (explorer.exe, svchost.exe)
  - 2. Otvaranje handle-a na taj proces s PROCESS_CREATE_PROCESS pravom
  - 3. Koristi NtCreateUserProcess (umjesto CreateProcessW) s 
       AttributeList kojem postavljamo PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
  - 4. Rezultat: Novi proces IZGLEDA kao da ga je pokrenuo explorer.exe

Tehnika: **Block DLL Policy**
  - Koristi PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES
  - Sprječava EDR DLL-ove da se inject-aju u naš novi proces

3.2 NETWORK MASQUERADING — Lažni promet
───────────────────────────────────────
C2 komunikacija mora izgledati kao legitiman web promet.

Tehnika: **Domain Fronting**
  - HTTP Host header pokazuje na legitimnu domenu (cdn.microsoft.com)
  - TLS SNI (Server Name Indication) pokazuje istu legitimnu domenu
  - Stvarni zahtjev ide na naš C2 preko CloudFront/Azure CDN
  - Rezultat: U logovima se vidi samo promet prema Microsoft CDN-u

Tehnika: **DNS-over-HTTPS (DoH) Tunneling**
  - Komunikacija ide preko DNS upita na DoH provider-e (Cloudflare, Google)
  - Podaci su enkodirani u DNS query/response polja
  - Svaki upit izgleda kao običan DNS lookup
  - Rezultat: Nikakav "sumnjiv" HTTP promet ne postoji

Tehnika: **Protocol Imitation**
  - Komunikacija izgleda kao Microsoft Teams API pozivi
  - Koristi legit user-agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) 
    AppleWebKit/537.36 Teams/24165.1410.2974.7830"
  - Payload je embeddan u JSON strukturu koja izgleda kao Teams poruka

3.3 JITTER — Anti-Temporal Analysis
───────────────────────────────────
Fiksni interval (npr. svakih 30 sekundi) je lako detektirati vremenskom 
analizom.

Tehnika: **Gaussian Distributed Jitter**
  - Bazni interval: 300 sekundi (5 minuta)
  - Random jitter: -150 do +150 sekundi (uniform distribution)
  - Sleep implementacija: NtDelayExecution (syscall, ne time.Sleep)
  - Još bolje: Koristiti "legitimate wait" — WaitForSingleObject na 
    handle koji signalizira "event" (izgleda kao normalan I/O wait)

  sleepTime := baseInterval + rand.Intn(300) - 150  // Gaussian-ish
  ldelay(sleepTime)  // ldelay = indirect syscall NtDelayExecution

3.4 PERSISTENCE — Nevidljivo Trajno Prisustvo
─────────────────────────────────────────────
Registry Run ključ je najstariji IOC u povijesti.

Tehnika: **WMI Event Subscription (System Classes)**
  - Kreira __EventFilter koji se okida na svaku login sesiju
  - Kreira __EventConsumer koji pokreće naš kod
  - Kreira __FilterToConsumerBinding za povezivanje
  - Kod se izvršava kao WMI provider — nema procesa, nema tragova

Tehnika: **Scheduled Task + COM Hijacking**
  - Kreira scheduled task koji izgleda kao Windows Update provjera
  - Task pokreće legitimni Windows binary koji ima 
    DLL Search Order hijack (credwiz.exe, cliconfg.exe)
  - Naš DLL je smješten u direktoriju s precedencom
  - Windows binary automatski učitava naš DLL

================================================================================
  4. LAYER 4: ENVIRONMENTAL — Inteligentna Samoočuvanja
================================================================================

4.1 HARDWARE FINGERPRINTING — Stvarna VM detekcija
─────────────────────────────────────────────────
Prethodni kod je imao osnovne provjere procesa. Moderni sandboxevi 
(pročisti detekciju).

Tehnika: **Multi-Factor Hardware Analysis**
  - CPUID: Provjera hypervisor prisutnosti (leaf 0x40000000)
  - RDTSC: Timing analiza — VM-ovi imaju "jitters" u timestamp-u
  - IN instruction: Provjera portova (VMware koristi specifične portove)
  - SMBIOS: Čitanje fizičke RAM tablice — VM-ovi imaju fiksne "signature"
  - Temperature: Fizički CPU-ovi imaju temperature, VM-ovi vraćaju 0
  - Disk SMART: Fizički diskovi imaju SMART podatke, virtualni ne

Tehnika: **Heuristic Sandbox Detection**
  - Mouse movement tracking: 5 minuta bez miša = sandbox
  - Memory pressure test: Alociraj 90% RAM-a — sandboxevi imaju limit
  - Network latency: Pinge 8.8.8.8 100 puta — VM-ovi imaju 
    konsistentni latency, fizički strojevi imaju varijaciju
  - Process enumeration: Broj procesa < 40 = novi sandbox

4.2 ANTI-DEBUG — Protekcija od analize
──────────────────────────────────────
Tehnika: **Multi-Vector Anti-Debug**
  - PEB.BeingDebugged (klasično, ali sandboxevi lažu)
  - NtQueryInformationProcess(ProcessDebugPort, ProcessDebugFlags, 
    ProcessDebugObjectHandle) — tri nezavisne provjere
  - CheckRemoteDebuggerPresent — externi debugger detekcija
  - Hardware breakpoints (Dr0-Dr3 registry check)
  - Timing checks: RDTSC oko kritičnih sekcija — ako je debugger 
    prisutan, razlika u ciklusima je ogromna
  - TLS callback-ovi: Kod se izvršava PRIJE main()-a — debuggeri 
    ne stignu postaviti breakpoint-e

4.3 SLEEP ACCELERATION DETECTION
────────────────────────────────
Sandboxevi "ubrzavaju" sleep pozive da uštede vrijeme.

Tehnika: **Time Skew Detection**
  - Zabilježi sistemsko vrijeme
  - Pozovi sleep(60) — trebalo bi trajati 60 sekundi
  - Zabilježi sistemsko vrijeme ponovo
  - Ako je stvarno prošlo < 55 sekundi, sandbox je ubrzao sleep
  - Reakcija: Dugotrajni "busy loop" koji troši CPU — forsira sandbox 
    da uspori (rate limit)

4.4 MEMORY ANALYSIS COUNTERMEASURES
────────────────────────────────────
Sandboxevi dump-aju memoriju i analiziraju stringove.

Tehnika: **Stack String Construction**
  - Stringovi se grade NA STACK-u, char po char
  - Nikada ne postoje kao kontinuirani blok u .data ili .rdata sekciji
  - Nakon korištenja, stack se overwrite-uje novim podacima

Tehnika: **Code Overwrite**
  - Kritične funkcije se kopiraju na heap PRIJE izvršavanja
  - Izvršava se heap kopija, ne originalna funkcija
  - Nakon izvršavanja, heap se oslobađa
  - Memory dump pokazuje samo "prazan" heap

================================================================================
  5. KONKRETNA PRIMJENA: Rewrite Strategija
================================================================================

Svaki file iz originalnog repozitorija prepisat ćemo primjenom gornjih 
principa. Ovo je plan:

5.1 main.go — "Entry Point Masquerading"
  - Umjesto očiglednog "main" flow-a, koristimo TLS callback
  - Sve stringove kriptirati runtime
  - Anti-debug provjere kao prvi korak (prije bilo čega)
  - Screenshot detekciju ukloniti — koristiti timing-based pristup
  - Sandbox evasion: hardware-based, ne process-based

5.2 beacon.go — "Legitimate Communication Imitation"
  - Ukloniti custom header-e (X-Aeterna-ID)
  - Koristiti Microsoft Teams user-agent
  - Payload enkodirati kao Teams poruke
  - Jitter implementirati indirect syscall-om
  - Domena fronting preko CDN-a

5.3 commands.go — "Living Off The Land"
  - Ukloniti direktno powershell izvršavanje
  - Koristiti WMI za izvršavanje (wmic process call create)
  - File operations preko Windows Backup API-ja
  - Screenshot preko legit PrintWindow API-ja

5.4 config.go — "Steganographic Storage"
  - Konfiguracija u NTFS Alternate Data Stream (ADS)
  - Enkripcija prevođenjem u "legit" format (XML, Registry binary)
  - UUID maskiran kao Windows Product ID

5.5 evasion.go — "Hardware-Aware Detection"
  - CPUID-based hypervisor detection
  - Timing analysis (RDTSC)
  - SMART disk data check
  - Memory pressure test

5.6 persistence.go — "System Integration"
  - WMI event subscription (ne registry)
  - COM hijacking putem legitimnih Windows binary-a
  - Scheduled task maskiran kao Windows Update

5.7 logger.go — "Zero-Trace Operation"
  - Ukloniti SVE file-based logiranje
  - Koristiti in-memory circular buffer (max 4KB)
  - Output ide SAMO preko C2 kanala, nikad na disk

5.8 screenshoot.go — "Native API Approach"
  - Ukloniti vanjsku biblioteku (kbinani/screenshot)
  - Koristiti PrintWindow/GDI directly
  - Rezultat: nema "suspicious" importa

5.9 system.go — "Minimal Footprint"
  - Koristiti indirect syscall umjesto standardnih API-ja
  - Username preko GetUserNameW (hashiranje identifikatora)
  - System info preko WMI (ne direktni API)

================================================================================
  6. KONCEPTUALNI PRIMJER: String Obfuskacija
================================================================================

Pokažimo kako izgleda princip na najvažnijem primjeru — stringovima.

PRISTUP 1: XOR s runtime ključem (PROBLEMATIČAN)
  - I dalje vidljiv XOR pattern u kodu
  - Key recovery je trivijalan s breakpoint-om

PRISTUP 2: Stack Construction + Polimorfni Decoder (ISPRAVAN)

  func dStr(enc []byte, salt byte) []byte {
      // Polimorfni decoder — mijenja se po build-u
      key := deriveKey() ^ uint32(salt)
      result := make([]byte, len(enc))
      for i := range enc {
          // Višestruka transformacija — ne samo XOR
          result[i] = enc[i] ^ byte(key) ^ byte(key>>8) ^ byte(i*7)
          key = (key * 0x08088405) + 1  // LCG PRNG
      }
      // Zero-out original buffer
      for i := range enc { enc[i] = 0 }
      return result
  }

  // Korištenje:
  buf := dStr([]byte{0x1A, 0x3F, 0x52, ...}, 0x42)
  // buf sadrži "kernel32.dll" — ali SAMO u ovom trenutku
  ptr := resolveAPI(hash(buf), hashFunc)
  for i := range buf { buf[i] = 0 }  // Uništi odmah

================================================================================
  7. KLJUČNA RAZMIŠLJANJA
================================================================================

7.1 "Don't Stand Out"
─────────────────────
Najčešća greška: pokušaj biti 100% nevidljiv. To je nemoguće. 
Pravi cilj: biti 99% identičan legitimnom software-u.

Legitiman program:
  - Ima import tablicu s 20-30 funkcija iz kernel32, user32, gdi32
  - Šalje HTTPS promet preko port 443
  - Čita/piše u %LOCALAPPDATA%
  - Ima registry ključeve za settings
  - Koristi GDI za grafiku
  - Ima WMI pozive za system info

Naš stealth program mora izgledati identično.

7.2 "Fail Securely"
───────────────────
Ako detekcija okrije analitičko okruženje:
  - NE izlaziti odmah (to je IOC)
  - NE pokušavati "disable" AV (to je trigger)
  - UMJESTO TOGA: ući u "degraded mode"
    * Komunikacija se zaustavlja
    * Sve operativne funkcije se gasi
    * Program se pretvara u običan "hello world" koji 
      legitimno radi nešto korisno (npr. system monitor)
    * U sustavu ostaje kao legitiman utility

7.3 "Defense in Depth je dvosjekli mač"
────────────────────────────────────────
EDR koristi layered defense. Mi koristimo layered evasion.
Razlika: EDR layer-i moraju SVI proći. Naši layer-i moraju SAMO 
JEDAN uspjeti.

  EDR: Detektiraj na LAYER 1 OR LAYER 2 OR LAYER 3 OR LAYER 4
  Mi:    Izbjegni na LAYER 1 AND LAYER 2 AND LAYER 3 AND LAYER 4

Međutim, ako bilo koji EDR layer ima false negative — prošli smo.
Ako bilo koji naš layer ima true positive — prošli smo.

Statistički: P(Detection) = P(L1_detect) × P(L2_detect|L1) × ...
P(Evasion)  = 1 - P(Detection)

Svaki novi layer EXPONENCIJALNO smanjuje vjerovatnoću detekcije.

================================================================================
  8. ZAKLJUČAK TEORIJSKOG DIJELA
================================================================================

Stealth nije trik. Stealth je disciplina. Svaka odluka u kodu mora 
proći kroz filter: "Kako ovo izgleda iz perspektive AV/EDR analitičara?"

Originalni kod imao je:
  - 15+ očiglednih stringova IOC-a ("Aeterna", "WindowsEssentials")
  - Direktne API importe iz ntdll.dll (instant flag)
  - Custom HTTP header-e ("X-Aeterna-ID")
  - Hardkodirane IP adrese (network IOC)
  - Registry Run ključ (persistence IOC)
  - File-based logging (disk forensics)
  - Fixni beacon interval (temporal IOC)

Stealth rewrite rješava SVE ove probleme kroz:
  - Runtime string decryption s hardware-derived ključem
  - Indirect syscalls bez direktnih importa
  - Domain fronting / DoH tunneling
  - WMI persistence (nema registry tragova)
  - In-memory logging (nema disk tragova)
  - Gaussian jitter (nema temporal pattern-a)

U nastavku slijedi PRAKTIČNI DIO — konkretni Go kod za svaki file.
================================================================================
