# PTCapture
 Intel PT Capture Kernel Module


Intel PT Capture Kernel Module



    [PTCapture module]                 [Kernel crash infra]             [Post-mortem tools]
  ┌────────────────────────┐      ┌──────────────────────────┐      ┌────────────────────────┐
  │  Intel PT Crash Tracer │      │      kdump / vmcore      │      │  vmcore + PT decoder   │
  ├────────────────────────┤      ├──────────────────────────┤      ├────────────────────────┤
  │  Setup PT (per-CPU)    │ ---> │  Crash → save all RAM    │ ---> │  Find PT metadata      │
  │  Run & log trace       │      │  (incl. PT buffers)      │      │  Extract PT buffers    │
  │  On panic: freeze PT   │      │                          │      │  Decode + visualize    │
  └────────────────────────┘      └──────────────────────────┘      └────────────────────────┘
            ▲
            │
      [Intel PT HW]
