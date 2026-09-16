# AmdTools64.sys — произвольный доступ к физической памяти из юзермода

Секьюрити-ресёрч драйвера `AmdTools64.sys` ("AMD Tools Driver" 1.7.16.219) —
AMD-подписанного кернел-драйвера, которого нет ни в одном публичном
дистрибутиве AMD. Драйвер наружу торит богатый набор `METHOD_BUFFERED`
IOCTL-ов, через которые можно из юзермода мапить, читать и писать **произвольную
физическую память с attacker-controlled адресом**. Итог — полностью рабочий
BYOVD-примитив ("bring your own vulnerable driver").

Насколько нам известно, в рекомендованном Microsoft блоклисте уязвимых
драйверов семпла пока нет.

## Пострадавший компонент

| Поле | Значение |
|---|---|
| Файл | `AmdTools64.sys` |
| Версия | 1.7.16.219 |
| Оригинальное имя | `amdtools64.sys` |
| SHA-256 | `891007BC9F3B55AE168FA60CCBB831CCDB5DCE4DA4A591D000806D5A2C6115C3` |
| Подпись | "Advanced Micro Devices Inc." (Sectigo RSA Code Signing CA, кросс-сертификат через Microsoft Code Verification Root) |
| Таймстамп сборки | 2022-06-22 (PE-заголовок) |
| PDB-путь | `C:\Project\AmdToolsDriver\src\AMD Special Tools Driver\x64\Release\amdtools64.pdb` |

Драйвер — PnP-шный. В `AddDevice` он создаёт девайс через
`IoCreateDeviceSecure` с SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)` (доступ только у
SYSTEM и админов) и регистрирует device-интерфейс с GUID
`{1232175B-1C34-41FD-B101-342D47B828AC}`. То есть для загрузки драйвера хватает
прав админа, а дальше перечисленные ниже IOCTL-ы сносят границу
админ→кернел в щепки.

## Примитивы произвольного доступа к физпамяти

### `0xFFF028A4` — мапим произвольную физическую память себе в юзермод (RW)

Структура запроса (`METHOD_BUFFERED`, вход и выход `>= 0x21` байт):

```c
struct MmapRequest {
    UINT64 PhysicalAddress; // +0x00 in:  физический базовый адрес (никем не проверяется)
    UINT32 Length;          // +0x08 in:  размер в байтах (тоже без проверок)
    UINT32 Status;          // +0x0C out: статус драйвера
    PVOID  PoolCtx;         // +0x10 out: аллокация на стороне драйвера (отдать в 0xFFF028A8 для анмапа)
    PVOID  UserVa;          // +0x18 out: юзермод-маппинг этой физической памяти
    UINT8  CacheType;       // +0x20 in:  0 = NonCached, 1 = Cached, 2 = WriteCombined
};
```

Хендлер делает `MmMapIoSpace` → `IoAllocateMdl` →
`MmBuildMdlForNonPagedPool` → `MmMapLockedPagesSpecifyCache(Mdl, UserMode, ...)`
и возвращает получившийся юзермод-адрес. Маппинг читается **и пишется**, так
что один вызов = полный read/write по ядру. `0xFFF028A8` освобождает ранее
выданный маппинг (`PoolCtx`).

### `0xFFF0281C` / `0xFFF02820` — one-shot блочное чтение / блочная запись

У обоих одинаковый запрос на 0x10C байт (вход и выход `>= 0x10C`):

```c
struct PhysBlockRequest {
    UINT64 PhysicalAddress; // +0x00 in: 64-битный физический адрес (без валидации)
    UINT16 Width;           // +0x08 in: сколько байт, 1..0x100
    UINT16 Status;          // +0x0A out: 0 = ок, 5 = MmMapIoSpace обломался, 6 = кривой width
    UINT8  Data[0x100];     // +0x0C in (запись) / out (чтение)
};
```

* `0xFFF0281C` (хендлер `0x1400026e8`): `MmMapIoSpace` → скопировать `Width`
  байт из замапленного в `Data` → `MmUnmapIoSpace` — **произвольное чтение**.
* `0xFFF02820` (хендлер `0x140003050`): `MmMapIoSpace` → скопировать `Width`
  байт из `Data` в замапленное → `MmUnmapIoSpace` — **произвольная запись**.

`MmMapIoSpace` вызывается с `MmCached`; учтите, что `MmMapIoSpace(0, ...)`
фейлится, так что физический адрес 0 — единственный «неюзабельный».

### Прочие примитивы чтения физпамяти

| IOCTL | Размер | Что делает |
|---|---|---|
| `0xFFF02888` | 0x20 | `MmMapIoSpace(Phys, Len)` → копия в пул → мап пула в юзермод; возвращает `PoolCtx` + `UserVa`. `Len` вообще без проверок. `0xFFF0288C` освобождает. |
| `0xFFF02824` | 0x2122 | Поиск паттерна по физпамяти: мапит `[Base, Base+WindowSize)`, тыкается с шагом `Stride` через `RtlCompareMemory` против `Pattern` (`ChunkSize <= 0x100`), при мэтче копирует до `ReadLength (<= 0x2000)` байт назад и возвращает адрес совпадения. |

### Прочие произвольные / почти произвольные примитивы записи

| IOCTL | Размер | Что делает |
|---|---|---|
| `0xFFF02894` | 0xC | **Запись** в регистр SMN (AMD System Management Network): база из MSR `0xC0010058`, замаскированная `0xFFFFFFF00000`, плюс полностью юзер-контролируемый офсет; byte/word/dword (`WRITE_REGISTER_*`) из запроса. |
| `0xFFF02890` | 0xC | Чтение SMN-регистра (та же адресация). |
| `0xFFF02884` | 8 | **Запись** в регистр APIC: мапит базу APIC из MSR `0x1B` (при необходимости сначала включая APIC через `WRMSR`), офсет `WORD[req] < 0x20`, значение `DWORD[req+4]`, возвращает старое значение. |
| `0xFFF02880` | 8 | Чтение регистра APIC (та же адресация). |
| `0xFFF02830` | 0xA | **Запись** в PCI configuration space через `HalSetBusDataByOffset`: `{Bus, Func, Dev, Width(1/2/4), Offset, Status, Value}`. В связке с BAR-маппингом ниже это даёт непрямой произвольный физический маппинг (переписали BAR → замапили его). |
| `0xFFF0282C` | 0xA | Чтение PCI configuration space через `HalGetBusDataByOffset`. |
| `0xFFF02834` / `0xFFF0283C` | 0x16 | Читают BAR произвольного PCI-девайса (`Bus/Dev/Func/Offset`) и мапят его в юзермод; `0xFFF02840` / `0xFFF02838` — парные анмапы. |

### Примитивы аллокации памяти

| IOCTL | Размер | Что делает |
|---|---|---|
| `0xFFF028AC` | 0x38 | `MmAllocateContiguousMemorySpecifyCache` + MDL + юзермод-маппинг аллокации; `0xFFF028B0` освобождает. |
| `0xFFF02868` / `0xFFF0289C` | 0x2E | `MmAllocatePagesForMdl` (диапазон физики задаёт атакующий) + юзермод-маппинг; `0xFFF0286C` / `0xFFF028A0` освобождают. |

### Полная таблица диспетчеризации IOCTL

Один диспетчер на `0x140005968`; `0xFFF028C0` переключает на
батч/command-list процессор. Адреса хендлеров — из билда 1.7.16.219.

| IOCTL | Хендлер | Мин. in/out | Функция |
|---|---|---|---|
| `0xFFF02800` | инлайн | 4 | вернуть версию `0x010710DA` |
| `0xFFF02804` | `0x1400027BC` | 0x14 | команда SMU/MP1 |
| `0xFFF02808` | `0x140003124` | 0x14 | команда SMU/MP1 |
| `0xFFF0280C` | `0x140002BD0` | — | команда SMU/MP1 |
| `0xFFF02810` | `0x140002BD0` | — | команда SMU/MP1 |
| `0xFFF02814` | `0x140002990` | 8 | команда SMU/MP1 |
| `0xFFF02818` | `0x1400032F0` | 8 | команда SMU/MP1 |
| `0xFFF0281C` | `0x1400026E8` | 0x10C | **чтение физпамяти (<= 0x100 Б)** |
| `0xFFF02820` | `0x140003050` | 0x10C | **запись в физпамять (<= 0x100 Б)** |
| `0xFFF02824` | `0x140002A38` | 0x2122 | **поиск паттерна по физике + блочное чтение** |
| `0xFFF02828` | `0x140001A44` | 8 | команда SMU/MP1 |
| `0xFFF0282C` | `0x140002818` | 0xA | **чтение PCI config** |
| `0xFFF02830` | `0x140003188` | 0xA | **запись PCI config** |
| `0xFFF02834` | `0x1400022FC` | 0x16 | **мап PCI BAR в юзермод** |
| `0xFFF02838` | `0x140002D70` | 0x16 | анмап |
| `0xFFF0283C` | `0x140001CAC` | 0x16 | мап PCI BAR (через копию в пул) |
| `0xFFF02840` | `0x140002C34` | 0x16 | анмап |
| `0xFFF02844` | `0x140002504` | 6 | команда SMU/MP1 |
| `0xFFF02848` | `0x1400029C0` | 3 | команда SMU/MP1 |
| `0xFFF0284C` | `0x140003320` | 3 | команда SMU/MP1 |
| `0xFFF02850` | `0x14000269C` | 2 | команда SMU/MP1 |
| `0xFFF02854` | `0x140003000` | 2 | команда SMU/MP1 |
| `0xFFF02858` | `0x140001C94` | 1 | команда SMU/MP1 |
| `0xFFF0285C` | `0x140006504` | 8 | команда SMU/MP1 |
| `0xFFF02860` | `0x14000261C` | 0xC | команда SMU/MP1 |
| `0xFFF02864` | `0x140002EF0` | 0xC | команда SMU/MP1 |
| `0xFFF02868` | `0x14000187C` | 0x2E | **MmAllocatePagesForMdl + мап в юзермод** |
| `0xFFF0286C` | `0x140001BC0` | 0x2E | освобождение |
| `0xFFF02870` | `0x140002668` | 0xC | команда SMU/MP1 |
| `0xFFF02874` | `0x140002F78` | 0xC | команда SMU/MP1 |
| `0xFFF0287C` | `0x140002DF8` | — | команда SMU/MP1 |
| `0xFFF02880` | `0x140002534` | 8 | чтение регистра APIC |
| `0xFFF02884` | `0x140002E00` | 8 | запись регистра APIC |
| `0xFFF02888` | `0x140001EF0` | 0x20 | **снапшот диапазона физики в юзермод** |
| `0xFFF0288C` | `0x140002CA8` | 0x20 | освобождение снапшота |
| `0xFFF02890` | `0x1400028B0` | 0xC | **чтение SMN-регистра** |
| `0xFFF02894` | `0x140003210` | 0xC | **запись SMN-регистра** |
| `0xFFF02898` | `0x140001C44` | 0xC | команда SMU/MP1 |
| `0xFFF0289C` | `0x140001960` | 0x2E | **MmAllocatePagesForMdl + мап в юзермод** |
| `0xFFF028A0` | `0x140001BC0` | 0x2E | освобождение |
| `0xFFF028A4` | `0x1400020E4` | 0x21 | **мап произвольной физической памяти (RW)** |
| `0xFFF028A8` | `0x140002D1C` | 0x21 | анмап |
| `0xFFF028AC` | `0x140001668` | 0x38 | **аллокация contiguous memory + мап в юзермод** |
| `0xFFF028B0` | `0x140001B30` | 0x38 | освобождение |
| `0xFFF028B8` | `0x140001C28` | 8 | команда SMU/MP1 |
| `0xFFF028BC` | `0x140002BB0` | 0x10 | команда SMU/MP1 |
| `0xFFF028C0` | `0x1400057E0` | — | батч/command-list процессор |
| `0xFFF028C4` | `0x140002BD0` | 2/0x78 | команда SMU/MP1 |
| `0xFFF02900` | `0x140001368` | 0x118/0x14 | форвард запроса в другой девайс |
| `0xFFF02940` | `0x140002A14` | 0x18 | форвард запроса в другой девайс |

Пункты с пометкой «команда SMU/MP1» прокидывают мелкие фиксированные
пейлоады в mailbox AMD SMU — глубоко мы их не аудировали; некоторые из них
тоже заканчиваются доступом через `MmMapIoSpace`.

## Proof-of-concept код

### `poc_amdtools64.cpp` — чтение физпамяти через `0xFFF028A4`

Ставит драйвер кернел-сервисом, создаёт root-enumerated PnP-девноду, открывает
device-интерфейс, мапит физику `0x53000000` (`Length = 0x200000`,
`MmNonCached`) в юзермод и дампит первые 64 байта.

```
cl /EHsc /W4 poc_amdtools64.cpp cfgmgr32.lib     (MSVC x64)
poc_amdtools64.exe C:\absolute\path\to\AmdTools64.sys
```

### `poc_amdtools64_write.cpp` — запись в физпамять через `0xFFF02820`

Сквозная и при этом crash-safe демонстрация **произвольной записи**:

1. ставит драйвер и биндит его к девноде (см. «Загрузка драйвера» ниже);
2. аллоцирует **AWE-страницу** (`AllocateUserPhysicalPages`, нужен
   `SeLockMemoryPrivilege`) — физический фрейм, *принадлежащий процессу*, так
   что тест гарантированно не покорраптит чужой кернел/девайс-памяти;
3. кидает в фрейм случайный 32-байтный маркер через свой юзермод-маппинг и
   проверяет, что read-примитив драйвера (`0xFFF0281C`) видит его по адресу
   `PFN << 12`;
4. пишет пейлоад `"AmdTools64 0xFFF02820 phys write"` по `phys + 0x800` через
   `0xFFF02820` и показывает, что байты появились в собственном виртуальном
   адресе процесса;
5. бонусом дергает `Width == 4` (DWORD) путь хендлера;
6. останавливает и удаляет сервис.

```
x86_64-w64-mingw32-g++ -O2 -static -o poc_amdtools64_write.exe \
    poc_amdtools64_write.cpp -lcfgmgr32 -lnewdev -lpsapi
poc_amdtools64_write.exe C:\absolute\path\to\AmdTools64.sys
```

Проверенный вывод (Windows 10 21H2 x64, KVM/QEMU VM):

```
[+] AWE frame mapped: PFN 0x1B1BAC -> physical 0x1B1BAC000
[+] read-back via 0xFFF0281C matches the marker
[*] writing 32 bytes via IOCTL 0xFFF02820 to physical 0x1B1BAC800...
[+] driver accepted the write (status = 0)
[+] PROOF: bytes appeared in OUR user-mode page @0000000001fb0800:
    AmdTools64 0xFFF02820 phys write
[+] DWORD write path verified (0x443342341 @phys 0x1B1BAC810)
```

## Загрузка драйвера на Windows 10 21H2

Драйвер — чисто PnP-шный (девайс создаётся только в `AddDevice`), а современная
Windows отказывается биндить голую root-девноду к сервису без драйвер-пакета
(«No compatible drivers found»; `UpdateDriverForPlugAndPlayDevices` фейлится с
`0xE000022F`, потому что у пакета нет каталога). PoC использует технику
**INF-сквоттинга**, которая работает без единого своего подписанного пакета:

1. создаём сервис (`CreateServiceW`);
2. создаём root-девноду `ROOT\AMDTOOLS64\0000` (`CM_Create_DevNodeW`);
3. вешаем на него hardware ID, совпадающий с *уже staged* драйвер-пакетом —
   например `ACPI\QEMU0001` из virtio `pvpanic.inf` (`CM_Add_IDW`) — и дергаем
   `CM_Setup_DevNode`: PnP ставит тот пакет и создаёт class node;
4. переписываем значение `Service` (и в `Enum\ROOT\AMDTOOLS64\0000`, и в
   `Control\Class\{...}\00NN`) на `AmdTools64`;
5. disable/enable девайса — PnP грузит уже `AmdTools64.sys`, и `AddDevice`
   регистрирует device-интерфейс.

Нужны админские права — стандартная BYOVD-модель угрозы. Для
AWE-верификации в `poc_amdtools64_write.cpp` аккаунту дополнительно нужно
право `SeLockMemoryPrivilege` («Блокировка страниц в памяти»).

## Подводные камни драйвера

* `MmMapIoSpace(0, ...)` фейлится, а диапазоны, накрывающие не-RAM дыры
  (VGA-диапазон, MMIO, за верхом RAM), отваливаются с `STATUS_NO_MEMORY`
  (`0xC0000017`) — актуально, когда скриптуешь read/search IOCTL-ы.
* `MmMapIoSpace` с `MmCached` фейлится на диапазонах где-то между 64 КиБ и
  1 МиБ (поиск через `0xFFF02824` проверенно работает с окнами 64 КиБ и
  падает с окнами 1 МиБ); путь `MmNonCached` у `0xFFF02888` тянет как минимум
  64 МиБ.
* Маппинг, который `0xFFF028A4` отдаёт в юзермод, — writable, так что примитив
  «чтения» по факту является read/write-примитивом.

## Что лежит в репе

| Файл | Описание |
|---|---|
| `AmdTools64.sys` | семпл уязвимого драйвера (AMD-подписанный) |
| `poc_amdtools64.cpp` | read-PoC через `0xFFF028A4` (мап физики → юзермод) |
| `poc_amdtools64_write.cpp` | write-PoC через `0xFFF02820` (AWE-верификация, обкатано на VM) |
| `amdtools64_loldrivers.yaml` | сабмит в LOLDrivers |
| `loldrivers_issue.md` | черновик ишью для LOLDrivers |
| `amd_psirt_report.txt` | черновик отчета для AMD PSIRT (coordinated disclosure) |

## Дискложаж

Зарепорчено в AMD PSIRT в рамках coordinated disclosure. На момент написания
инфа не паблилась. Не используйте этот код против систем, которыми не владеете
или на которых нет явного разрешения на тестирование.
