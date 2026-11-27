# Claude Guard

Claude Desktop ходит в интернет **только через ваш прокси**, остальной компьютер работает напрямую. Вставляете в окно ссылку `vless://` (или конфиг Xray) — служба поднимает собственный [sing-box](https://github.com/SagerNet/sing-box) и направляет в прокси только процессы Claude. Если прокси или sing-box упали, Claude не может выйти в сеть вообще: системный firewall не пускает его мимо туннеля.

## Как это работает

- Служба запускает `sing-box.exe` с TUN-адаптером `ClaudeGuard`. Правило маршрутизации по пути процесса: всё из пакета Claude Desktop (`WindowsApps\Claude_*__pzs8sxrjxfjjc\`) → прокси, остальное → напрямую.
- DNS-запросы к доменам Claude (`anthropic.com`, `claude.ai`, `claude.com`, `claudeusercontent.com`) разрешаются через прокси — провайдер их не видит.
- Для всех `.exe` Claude Desktop создаются правила Windows Firewall: Claude заблокирован на **любом локальном адресе, кроме адреса TUN sing-box** (и loopback). Это покрывает LAN, Wi-Fi, адаптеры других VPN и весь IPv6.
- Трафик к доменам Claude от любого процесса (в том числе встроенный Claude Code, помощники вне пакета) sing-box тоже отправляет в прокси.
- Пока Claude запущен, служба каждые 2 с проверяет прокси лёгким HTTP-запросом `generate_204` (около 1 КБ). Полная TLS-проверка `api.anthropic.com` — после запуска sing-box, по кнопке «Проверить сейчас» и раз в 30 минут. **Пока Claude закрыт, проверок нет и трафик прокси не тратится**; при запуске Claude проверка выполняется сразу. Один сбой не блокирует Claude, нужна серия из 3 результатов.
- Если sing-box упал, TUN пропал или прокси не отвечает — блок на всех интерфейсах, через 5 с Claude закрывается. sing-box перезапускается автоматически (с нарастающей паузой при повторных падениях).
- После обновления Claude (новый каталог пакета) правила firewall пересоздаются сразу, как только запустится новая версия.
- Сторожевая задача раз в минуту проверяет службу. Если служба недоступна, включается аварийный блок.

## Требования

- Windows 10 / 11, x64
- Включённый Windows Firewall
- Claude Desktop (пакет MSIX)
- Ссылка или конфиг прокси: VLESS (TLS / REALITY, tcp / ws / grpc / httpupgrade / h2), VMess, Trojan, Shadowsocks, Hysteria2, SOCKS5, HTTP(S)
- Права администратора для установки и смены профиля

.NET и sing-box устанавливать не нужно: всё в архиве.

## Вместе с Happ / другим VPN

Можно: Claude идёт через Claude Guard, остальные программы — через ваш VPN. Гайд есть и в самом приложении («Гайд: вместе с Happ / другим VPN»).

1. В Happ включите режим **«Системный прокси»**, **TUN-режим выключите**. Два TUN мешают друг другу — Claude Guard заблокирует Claude с причиной `ROUTE_NOT_VIA_TUN`.
2. PAC-режим тоже выключите.
3. Claude Guard (служба) сам добавляет домены Claude в исключения системного прокси для всех вошедших пользователей и возвращает их, если VPN-клиент их сотрёт (`manageSystemProxyBypass`). Если исключения не держатся или включён локальный PAC — Claude блокируется с причиной `SYSTEM_PROXY_CONFLICT`.

## Установка

1. Скачайте `ClaudeGuard-<версия>-win-x64.zip` со страницы [Releases](../../releases/latest).
2. Распакуйте архив в любую папку (не в `Program Files`).
3. Запустите `scripts\install.cmd`, согласитесь на запрос UAC.
4. В открывшемся окне Claude Guard нажмите **«Импорт профиля…»**, вставьте ссылку или конфиг, нажмите «Применить» (будет ещё один запрос UAC).

Пока профиль не задан, Claude заблокирован.

Установщик:
- сохранит резервную копию правил firewall и конфига;
- скопирует файлы в `C:\Program Files\ClaudeGuard`;
- проведёт самопроверку (физический блок работает; если профиль уже есть — прокси и TUN тоже);
- создаст службу `ClaudeGuard` (автозапуск) и задачи `ClaudeGuardUi`, `ClaudeGuardWatchdog`;
- при ошибке откатит всё назад, и Claude останется разблокированным.

Windows SmartScreen или антивирус могут предупредить о неподписанных файлах — сборки не подписаны. Исходный код открыт, можно собрать самому.

## Что можно импортировать

- Ссылки: `vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://` (`hy2://`), `socks5://[user:pass@]host:port`, `http(s)://[user:pass@]host:port`, а также подписку в base64 (берётся первая ссылка).

  SOCKS5 и HTTP не шифруют соединение с прокси: провайдер видит, к какому сайту вы подключаетесь. Если Claude у провайдера заблокирован, нужен VLESS/Trojan и т. п.
- Конфиг **Xray** (JSON): берётся первый outbound `vless` / `vmess` / `trojan` / `shadowsocks`.
- Конфиг **sing-box** или один его outbound.

Не поддерживается (нет в sing-box): транспорт XHTTP / SplitHTTP, TCP с HTTP-обфускацией, цепочки outbound (`detour`).

Перед сохранением профиль проверяется командой `sing-box check`. Профиль хранится в `C:\ProgramData\ClaudeGuard\secrets` — доступ только у SYSTEM и администраторов.

## Использование

| Цвет | Состояние |
|---|---|
| Зелёный | прокси проверен, Claude работает только через него |
| Синий | идёт проверка, Claude заблокирован |
| Жёлтый | нет профиля или проверка прокси не прошла — Claude заблокирован |
| Красный | sing-box/туннель не работают (Claude заблокирован и закрыт) или защита отключена вручную |

«Отключить защиту» останавливает sing-box и снимает правила firewall — Claude пойдёт напрямую. Нужен UAC. Включить обратно — той же кнопкой.

Журналы: `C:\ProgramData\ClaudeGuard\logs` (вывод sing-box тоже попадает туда, не больше 30 строк в минуту).

## Настройка

`C:\ProgramData\ClaudeGuard\config.json` создаётся при первом запуске. После правки: `Restart-Service ClaudeGuard`.

| Параметр | По умолчанию | Описание |
|---|---|---|
| `tunInterfaceName` | `ClaudeGuard` | имя TUN-адаптера sing-box |
| `tunAddress` | `172.19.0.1/30` | адрес TUN; смените, если подсеть занята |
| `tunStack` | `gvisor` | стек TUN: `gvisor`, `system`, `mixed` |
| `manageSystemProxyBypass` | `true` | держать домены Claude в исключениях системного прокси |
| `extraProxyProcessRegex` | `[]` | дополнительные процессы в прокси (RE2 по полному пути), например отдельный Claude Code CLI |
| `remoteDnsServer` | `1.1.1.1` | DoH-сервер для доменов Claude (через прокси) |
| `remoteDnsDomains` | anthropic.com, claude.ai, … | домены, чей DNS идёт через прокси |
| `probeTargets` | api.anthropic.com, www.cloudflare.com | куда проверяется прокси |
| `probeUrls` | cp.cloudflare.com, www.gstatic.com `/generate_204` | лёгкая проверка (HTTP 204), вторая — только если первая не ответила |
| `fullTlsCheckMinutes` | `30` | как часто полная TLS-проверка `probeTargets`; `0` — всегда TLS (больше трафика) |
| `probeOnlyWhileClaudeRuns` | `true` | не проверять прокси, пока Claude закрыт |
| `probeFailuresToBlock` | `3` | сколько неудачных проверок подряд до блока |
| `killClaudeOnFailure` | `true` | закрывать Claude при отказе прокси |
| `killDelaySeconds` | `5` | задержка перед закрытием |
| `autoRestartClaude` | `true` | запускать Claude после восстановления |

## Удаление

`scripts\uninstall.cmd`. Удалит службу, задачи, правила firewall, остановит sing-box и удалит файлы программы. Журналы, конфиг и профиль останутся, если не указать `-PurgeData`.

Если служба сломалась и Claude остался заблокированным (PowerShell от администратора):

```powershell
& "C:\Program Files\ClaudeGuard\ClaudeGuard.Service.exe" --remove-rules
```

## Сборка из исходников

Нужен [.NET SDK 10](https://dotnet.microsoft.com/download). sing-box (версия и SHA256 закреплены в `scripts\singbox.ps1`) скачивается с GitHub при сборке и кешируется в `.cache\`.

```powershell
scripts\build.ps1      # разработческая сборка в dist\
scripts\package.ps1    # самодостаточный релизный zip в release\
```

Релиз на GitHub собирается автоматически при пуше тега `v*`.

## Ограничения

- В прокси направляется только Claude Desktop (и процессы из `extraProxyProcessRegex`), не браузер.
- Проверки и маршрут идут по IPv4; IPv6-трафик Claude блокируется firewall на физических интерфейсах.
- Защита основана на Windows Firewall. Локальный администратор может её обойти; служба восстанавливает изменённые правила, но гарантий против администратора нет.

## Лицензия

MIT, см. [LICENSE](LICENSE). sing-box распространяется под GPL-3.0 (лицензия лежит рядом с `sing-box.exe`).
