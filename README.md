# MappedImagesDetector — Windows Memory Scanner for Antivirus & EDR

**Short description / SEO meta**: *MappedImagesDetector is a native C++20 Windows memory-scanning tool built for antivirus and EDR use — detects manual-mapped DLLs, erased PE headers, suspicious mapped images, IAT/CRT thunk anomalies and other memory-based stealth techniques used by modern malware.*

> ?? **Defensive-only project.** This repository is explicitly for malware analysis, incident response, and defensive engineering. Do not use the techniques here to produce or deploy malware. Use responsibly and in accordance with law.

---

## Why this project exists (TL;DR)
Modern malware frequently avoids disk-based indicators by manually mapping DLLs into process address spaces, erasing or corrupting PE headers, or creating executable regions with fake imports. Traditional on-disk scanners miss these threats. **MappedImagesDetector** finds suspicious mapped images in process memory and flags indicators of manual mapping and in-memory-only malware — the kind of stealth techniques commercial AV and EDR products must detect.

**SEO keywords included**: antivirus, EDR, memory scanner, manual-mapped DLL detection, erased PE header, IAT anomaly, Windows memory forensics, in-memory malware detection.

---

## Key features (antivirus-focused)

- **Detect manual-mapped DLLs** — identify modules that appear in memory without matching loaded modules on the process' LDR list.
- **PE header inspection** — detect erased or tampered PE headers and tampered section tables.
- **IAT & thunk anomaly detection** — spot IAT sequence inconsistencies and CRT thunk stubs commonly present in manual-mapped code.
- **Executable-only region detection** — find suspicious RWX/EXEC-only pages that often host shellcode or unpacked payloads.
- **Entropy & heuristic checks** — entropy analysis and heuristic scoring to reduce false positives.
- **Lightweight native C++20 implementation** — minimal dependencies, designed for integration with antivirus/EDR stacks.
- **Test harness & unit tests** — `TestModule/` provides safe, local test cases for validating detection logic.
- **Extensible scoring** — generate a risk score per finding for integration into threat triage and automated response.

---

## How it helps defenders (Concrete use cases)
- **Incident response:** Find in-memory implants on compromised endpoints that disk scanners missed.
- **Behavioral monitoring:** Add memory-based indicators to EDR telemetry for better context-aware blocking.
- **Malware research:** Rapidly identify suspicious mapped images while analyzing samples in a sandbox.
- **False-negative reduction:** Complement on-disk signatures with memory heuristics to catch modern in-memory-only threats.

---

## High-level detection methods (non-abusive, defensive detail)
The project combines multiple defensive heuristics rather than publishing exploit code:

- Enumerate process virtual memory ranges and compare mapped images to the process module lists (PEB/LDR).
- Read and validate in-memory PE headers where present; flag erased or inconsistent headers.
- Validate Import Address Table (IAT) stubs and common CRT thunk patterns used by manual mappers.
- Check for pages with suspicious protection flags (e.g., NX-disabled or RWX) and atypical section alignment.
- Compute entropy and basic signatures for anomalous sections.
- Produce a **Ban / Risk Confidence Score** per anomaly (configurable threshold for triage).

---

## Repository layout
```
AnomaliesDetector/       # core detection library and executable
TestModule/               # safe test DLL used during development
docs/                     # documentation, threat model and blog-ready assets
MappedImagesDetector.sln  # Visual Studio solution
LICENSE                   # license file (MIT recommended for tooling)
```

---

## Requirements
- Windows 10 or later (x64 recommended)
- Visual Studio 2019 / 2022 with C++ workload
- MSVC toolset with C++20 (`/std:c++20`)

---

## Build & quick start
1. Open `MappedImagesDetector.sln` in Visual Studio.
2. Select `x64` and `Release` (recommended).
3. Build (Build -> Build Solution) or run from Developer Command Prompt:

```powershell
msbuild MappedImagesDetector.sln /p:Configuration=Release /p:Platform=x64
```

4. Built binaries appear under `AnomaliesDetector\x64\Release`.

**Runtime**: run the scanner as an elevated user for full process enumeration. The test harness in `TestModule` is designed for local testing only — do not deploy it to production.

---

## Usage & integration (AV / EDR guidance)
- **Standalone**: run on-demand to produce a JSON/CSV report of memory anomalies for forensic analysis.
- **EDR integration**: call the core library from an EDR sensor to enrich endpoint telemetry with memory-mapped anomalies.
- **Automated response**: use the risk confidence score to trigger containment workflows or further automated analysis.

**Logging**: the project uses `CLogger` with configurable verbosity. For production, forward logs to your centralized SIEM or EDR telemetry.

---

## False positives & tuning
Memory scanning produces noisy signals. To reduce false positives:

- Tune risk thresholds and whitelist known internal injectors/tooling.
- Use whitelist paths/hashes and parent process heuristics.
- Correlate findings with runtime behavior (network, process creation, module load events).
- Use entropy and signature checks only as part of a multi-signal confidence model.

---

## Testing & validation
- Use the included `TestModule` to validate detection of manual-mapped test payloads in a controlled lab.
- Run the scanner in a VM snapshot to validate behavior against benign applications and record false-positive rates.
- Add CI integration for builds and unit tests (recommended: GitHub Actions for Windows runners).

---

## Threat model
Target threats: memory-only implants, manual-mapped DLLs, reflective loaders, erasing PE header techniques, packers and in-memory unpacked payloads. Not intended for kernel rootkit discovery (use kernel-mode tools for that use case).

---

## Contributing (defensive engineering welcome)
1. Fork the repo.
2. Create a feature branch (`feature/<descriptive-name>`).
3. Add tests, run builds on Windows x64.
4. Open a PR with clear description, tests and reproducible steps.

**Note:** maintainers will reject pull requests that add offensive or malware-building content. This is a defensive project only.

---

## License
If absent, add an MIT license to maximize adoption in security projects and research. See `LICENSE`.

---

## Viral & outreach assets (use to promote responsibly)
**Suggested tweet (short & clicky):**
```
New tool: MappedImagesDetector — finds manual-mapped DLLs & in-memory implants that disk AV misses. Built in native C++20 for Windows. Defensive-only. ?? Fork + test: <github-repo> #infosec #malware #EDR #antivirus
```

**LinkedIn post (longer):**
```
If you're building defensive tooling or EDR telemetry, disk-based detection isn't enough. I released MappedImagesDetector — a native C++ memory scanner that detects manual-mapped DLLs, erased PE headers, and other in-memory stealth techniques used by modern implants. It's lightweight, fast, and designed for integration with SIEM/EDR. Defensive-only. Fork, validate, and contribute: <github-repo>
```

**Blog post outline (1,000–1,500 words):**
1. Intro: Why in-memory malware is the next frontier
2. Anatomy of manual-mapped DLLs and common stealth tricks
3. How MappedImagesDetector identifies them (approach, heuristics)
4. Example incident response workflow
5. Results from internal testing (false-positive rates, detection examples)
6. How to integrate with your EDR
7. Call to action: fork, test, contribute

**Suggested hashtags**: `#infosec #malware #EDR #antivirus #memoryforensics #cybersecurity`

---

## Contact
For issues and feature requests open a GitHub issue. For sensitive malware samples or incident coordination, contact the maintainers privately by the channels listed in the repository.

---

*This README focuses the original project toward antivirus and EDR use: defensive heuristics, integration advice, test harness guidance, and outreach assets to increase adoption while preventing misuse.*

