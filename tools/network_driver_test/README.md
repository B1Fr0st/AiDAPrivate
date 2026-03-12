# NetworkDriverTestTool

Standalone C++ test harness for end-to-end validation of the driver's network feature set.

## What It Tests

Required MCP/network features:

- driver_inject_packet
- driver_modify_packet_rule
- driver_redirect_traffic
- driver_reassemble_stream
- driver_deep_inspect
- driver_intercept_hold
- driver_kill_connection
- driver_spoof_dns
- driver_bandwidth_monitor
- driver_list_interfaces
- driver_export_pcap
- driver_network_fingerprint

Additional network driver paths:

- capture pipeline (start/status/get packets/stop)
- DNS log retrieval
- connection enumeration
- WFP callout enumeration
- socket handle enumeration
- TCPIP connection dump
- filter add/remove/clear
- optional sniff network buffers (when instruction address and register indexes are supplied)

## Build

The target is enabled by default on Windows:

- target name: NetworkDriverTestTool
- output: build/Release/NetworkDriverTestTool.exe

Example build command (Visual Studio bundled CMake):

```
"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" -S . -B build
"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" --build build --config Release --target NetworkDriverTestTool
```

## Run

Basic run:

```
build\Release\NetworkDriverTestTool.exe
```

Run with output PCAP path and non-strict mode:

```
build\Release\NetworkDriverTestTool.exe --pcap-out tools\network_driver_test\latest_test_capture.pcap --non-strict
```

Optional sniff test arguments:

```
--sniff-address 0xFFFFF80012345678
--sniff-buffer-reg 2
--sniff-size-reg 8
--sniff-tid 1234
--sniff-bp-index 0
```

## Exit Codes

- 0: all tests passed
- 3: one or more tests failed
- 1/2: startup failure (WSA or driver connection)









please reverse engineer the provided driver using STRICTLY ONLY THE KERNEL MODE DRIVER TOOLS.

currently, 0xQL0Vupp5MDYwZMGNh6ykUEiZriX.sys is RUNNING IN THE SYSTEM!!! (it might not be in disk anymore)

Please try to find a vulnerability within its packing, virtualization, obfuscation and encryption.

