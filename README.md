# VmModem

A virtual Hayes-compatible 56k modem on a Windows named pipe, with a built-in
dial-up "ISP" behind it. Point a VM's COM1 at the pipe, have Trumpet Winsock (or any
PPP/SLIP dialer) dial any number, and the VM gets onto the host's internet connection.

No drivers, TAP adapters, or admin rights are needed. Traffic goes through a
user-mode NAT (similar to QEMU's "slirp"): the guest's TCP connections and UDP flows
end inside VmModem and are re-opened as ordinary sockets on the host.

```
 VM (Win 3.1 + Trumpet)          VmModem.exe (host)
 ┌───────────────────┐  named   ┌──────────────────────────────────────────────────┐
 │ Trumpet Winsock   │  pipe    │ Hayes AT modem ─► login prompt ─► PPP / SLIP     │
 │   PPP/SLIP        ├─────────►│                                    │             │
 │ COM1 (16550 UART) │ \\.\pipe │                     user-mode NAT ◄┘             │
 └───────────────────┘ \vmmodem │      TCP / UDP / ICMP echo / DNS ─► host sockets ├─► Internet
                                └──────────────────────────────────────────────────┘
```

## Build

Open `VmModem.sln` in Visual Studio 2022 and build, or from a terminal:

```bash
dotnet build -c Release
```

To get a single-file exe (requires the .NET 8 runtime on the machine):

```bash
dotnet publish src/VmModem -c Release -r win-x64 --self-contained false -p:PublishSingleFile=true -o publish
```

## Run

```bash
VmModem.exe
```

This creates `\\.\pipe\vmmodem` and waits for the VM. The VM can disconnect and
reconnect as often as it likes. If the VM is the side that creates the pipe, use
`--connect` (see the table below).

| Option | Meaning |
|---|---|
| `-p, --pipe <name>` | Pipe name or full path (default `vmmodem`) |
| `-c, --connect` | Connect to a pipe the VM created, instead of creating it |
| `--no-pipe` | Don't use a pipe (use with `--tcp`) |
| `-t, --tcp <port>` | Also accept raw serial-over-TCP on `127.0.0.1:<port>` |
| `-b, --baud <bps>` | Pace data to the VM at this line rate (default `56000`; `0` = unlimited) |
| `--session login\|ppp\|slip` | After CONNECT: login prompt (default), straight to PPP, or straight to SLIP |
| `--auth none\|pap\|chap` | Ask the PPP client to authenticate (any username/password is accepted) |
| `--dns <ip>` | Upstream DNS server (repeatable); default is the host's own DNS servers |
| `--guest-ip <ip>` | Address given to the VM (default `10.0.2.15`) |
| `--dial-delay <ms>` | Simulated dialing time before CONNECT (default 2000) |
| `--no-loopback` | Don't map `10.0.2.2` to the host's `127.0.0.1` |
| `-v` | Debug detail: decoded PPP negotiation, every connection, every dropped packet and why |
| `-vv` | ...plus every IP packet |
| `-vvv` | ...plus a hex dump of all serial bytes in both directions |
| `--log <file>` | Log file location (default `%LOCALAPPDATA%\VmModem\vmmodem.log`) |
| `--no-log` | Don't write a log file |

The log file is always written, with every packet logged whatever the console level.
Hex dumps are only added with `-vvv`. At 50 MB it rolls over to `vmmodem.1.log`.
In Visual Studio, the run button's drop-down has profiles for `-v`, `-vvv` and `--connect`.

### Network as seen from the VM

| | |
|---|---|
| VM address | `10.0.2.15` (assigned by IPCP for PPP; set it by hand for SLIP) |
| Netmask | `255.255.255.0` |
| Gateway | `10.0.2.2`. Connections to this address go to the **host's 127.0.0.1**, so services running on the host are reachable. |
| DNS server | `10.0.2.3` (relays to the host's DNS; falls back to the Windows resolver) |

## Hooking up the VM's COM1

Who creates the pipe decides whether VmModem needs `--connect`:

| Hypervisor | VM setting | VmModem command |
|---|---|---|
| **Hyper-V** (Generation 1 VMs only) | `Set-VMComPort -VMName "Win311" -Number 1 -Path \\.\pipe\vmmodem` | `VmModem --connect`, **run as Administrator** |
| **VirtualBox** | Serial Ports → Port 1: COM1, Port Mode **Host Pipe**, Path `\\.\pipe\vmmodem`, *Connect to existing pipe* **unchecked** | `VmModem --connect` |
| VirtualBox (alternative) | Same, but *Connect to existing pipe* **checked** (start VmModem first) | `VmModem` |
| **VMware Workstation** | Serial port → Use named pipe `\\.\pipe\vmmodem`, *This end is the client*, *The other end is an application* | `VmModem` |
| VMware (alternative) | *This end is the server* | `VmModem --connect` |
| **QEMU** | `-serial pipe:vmmodem` | `VmModem --connect` |
| QEMU over TCP | `-serial tcp:127.0.0.1:2323` | `VmModem --no-pipe --tcp 2323` |
| **DOSBox / DOSBox-X** | `serial1=nullmodem server:127.0.0.1 port:2323 transparent:1` | `VmModem --no-pipe --tcp 2323` |

There are no modem-control lines (DTR/DCD) over a pipe, so a hang-up has to come from
`+++` and `ATH`, a PPP Terminate-Request, or the `logout` command. Trumpet already
hangs up all three ways.

## Setting up Trumpet Winsock

**File → Setup**

- **Internal PPP** (Trumpet 2.1+ / 3.0), or **Internal SLIP**
- IP address: `0.0.0.0` for PPP (it's assigned to you), `10.0.2.15` for SLIP
- Netmask `255.255.255.0`, Default Gateway `10.0.2.2`, Name server `10.0.2.3`
- SLIP port `1`, baud rate `57600` or `115200` (any rate works; the real pacing is VmModem's `--baud`)
- **Van Jacobson CSLIP compression: off** (not supported; PPP clients that ask for it are refused and carry on without it)
- Online status detection: **None** (the pipe carries no DCD)
- If Trumpet hangs on the first dial, try unchecking *Hardware handshake*
- MTU / MSS / RWIN: the defaults are fine. If transfers stall, try MTU 576, MSS 536, RWIN 2144.

**Dialler → Login**

The stock `login.cmd` works as it is. VmModem behaves like an old terminal server:

```
ATDT<anything>        ->  CONNECT 56000
Username:             ->  (anything)
Password:             ->  (anything)
vmmodem>              ->  ppp | slip
Your IP address is 10.0.2.15
```

PPP frames are also detected automatically at any prompt, so a dialer that starts PPP
right after CONNECT works too. You can also do it by hand: *Dialler → Manual login*,
type `ATDT1`, wait for `CONNECT`, then press Esc.

**Dialler → Bye** sends `+++` and `ATH`, which hangs up cleanly.

### Browsing the modern web

The NAT passes any TCP/UDP traffic. Today's HTTPS sites still won't load in a 1990s
browser, because it can't speak modern TLS. Run a translating proxy on the host, for
example WebOne, and set the browser's HTTP proxy to `10.0.2.2:<port>`. Remember that
`10.0.2.2` is the host's localhost.

## Troubleshooting

Open `%LOCALAPPDATA%\VmModem\vmmodem.log`, which holds the detailed version of the
console output, and work down this list until something is missing:

| You should see | If it's missing |
|---|---|
| `[pipe] serial line connected` | The VM isn't attached to the pipe. Check who creates the pipe (`--connect`, see above), and power-cycle the VM after changing its serial settings. |
| `VM> ATZ` / `modem> OK` | Nothing from the dialer is arriving. Trumpet is using a different COM port than the one attached to the pipe. |
| `CONNECT 56000 - carrier up` | The dial was aborted. Look for `Dial aborted by DTE`. |
| `PPP: LCP up` then `PPP: IPCP up ... Online!` | Look for the `still not online after 10 s` warning. It says which step stalled. `-v` shows every option exchanged. |
| `First IP packet from VM: ...` | PPP is up but no packets are arriving. Is Trumpet set to the same mode (PPP vs SLIP)? |
| `Ping x.x.x.x ...: reply in N ms` | A line ending `TimedOut` means the host itself got no reply. Check with `ping` on the host; some sites block ICMP. |

Start with `ping 10.0.2.2`. VmModem answers that itself, so it tests the serial line and
PPP without involving the internet.

If VmModem logs `reply in N ms` but Trumpet still shows nothing, the reply is
getting lost on the way into the VM. Look for `bad checksum` warnings, which mean
bytes are being lost or changed on the serial line. Make sure the guest's COM port
isn't using XON/XOFF flow control, or try a slower line with `--baud 19200`.

If the console says `VM is sending PPP data but the modem isn't connected`, the call
dropped (or VmModem was restarted) but the dialer still thinks it's online. Hang up in
Trumpet and dial again. Trumpet's stock `login.cmd` also waits for carrier detect after
CONNECT, which a pipe can't provide. Comment out its `wait ... dcd` line to skip that
pause.

## Supported AT commands

`AT`, `ATZ`, `AT&F`, `ATE0/1`, `ATV0/1`, `ATQ0/1`, `ATXn`, `ATIn`, `ATSn=v`, `ATSn?`,
`ATD[T|P]<number>`, `ATA`, `ATH`, `ATO`, `A/`, and `+++` escape with guard time (S2/S12).
Everything else in common init strings (`&C1 &D2 &K3 \N3 %C0 Mx Lx +MS=…`) is accepted
and answered with `OK`.

## Limitations

- Outbound only: there's no port forwarding into the VM. This also means active-mode
  FTP won't work, so use passive mode.
- IPv4 only. IP fragments sent *by* the guest are dropped. Large packets sent *to* the
  guest are fragmented.
- No VJ header compression (CSLIP / PPP VJ).
- ICMP: echo (ping) works, including Time Exceeded so `tracert` shows hops; no other
  ICMP types are relayed.

## Testing

`tests/VmModem.TestClient` acts as the VM. It dials, logs in, negotiates PPP (or SLIP),
then checks ping, DNS, raw UDP, a local TCP transfer through 10.0.2.2 (verified byte for
byte), an HTTP fetch of example.com, refused connections and hang-up. `--drop <pct>`
throws away that share of incoming frames to exercise TCP retransmission.

```bash
VmModem --pipe vmmodem-test --tcp 23456 --baud 0
```

```bash
dotnet run --project tests/VmModem.TestClient -- --pipe vmmodem-test --drop 5
```

```bash
dotnet run --project tests/VmModem.TestClient -- --tcp 23456 --slip
```

Other options: `--size <bytes>` for the local transfer, `--no-internet`, and
`--pipe-server`, which makes the test client create the pipe so you can test
`VmModem --connect`.

## Source layout

| File | What it does |
|---|---|
| `Program.cs` | Command line, pipe server/client loops, TCP listener |
| `Session.cs` | One serial connection: reader, event loop, writer |
| `SerialOut.cs` | Output queue to the VM with baud-rate pacing |
| `Modem.cs` | Hayes AT command set, dialing, `+++` escape |
| `OnlineSession.cs` | Terminal-server login, PPP/SLIP auto-detect |
| `Link/PppLink.cs`, `Link/Hdlc.cs` | PPP: LCP, PAP/CHAP, IPCP (address + DNS), HDLC framing |
| `Link/SlipLink.cs` | SLIP framing |
| `Net/NatStack.cs` | IP routing, UDP/ICMP NAT, address mapping |
| `Net/TcpConn.cs` | Per-connection TCP endpoint (retransmit, flow control) relayed to a host socket |
| `Net/UdpBinding.cs`, `Net/DnsForwarder.cs` | UDP NAT and the 10.0.2.3 DNS relay |
