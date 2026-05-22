# Live Run Validation

## May 22, 2026 SIFT Run

The VMware-backed demo path was exercised against the sample evidence under
`/cases/R&M` on May 22, 2026.

Probe result:

- VMX path: `E:\Ollama\SIFT\SIFT.vmx`
- VMware Tools state: `installed`
- Guest user: `sansforensics`
- Guest tools observed for the current lanes included `python3`, `ewfinfo`,
  and `fls`.

Full artifact-preparation run:

- Driver output root: `artifacts/rm-live-demo-20260522`
- Correction run status: `needs_review`
- Full case run status: `ok`
- Full case benchmark scores: PCAP `18 / 18`, disk `16 / 16`, Autoruns
  `8 / 8`, registry `9 / 9`, UserAssist `9 / 9`, memory `7 / 7`
- Scenario alignment score: `6 / 6`
- Claim accuracy review: passed

The correction manifest captured a `lane_adjusted` event for the discovered
memory lane because its search terms still contained `pivot-to-review`.

## Recording Path

The full VMware run is suitable for preserved submission artifacts but is too
long to wait through during a five-minute recording. The quick recording path
was also exercised against discovered real `/cases/R&M` memory evidence:

```powershell
$env:SIFT_GUEST_PASSWORD='forensics'
.\scripts\run-rm-live-demo.ps1 `
  -OutputRoot '.\artifacts\rm-live-correction' `
  -QuickCorrection `
  -CorrectionOnly
```

The verified quick run completed discovery and emitted the same reviewable
memory-lane correction trace before downstream correlation was skipped for lack
of completed PCAP and disk summaries.
