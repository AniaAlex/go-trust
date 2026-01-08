# Archived Documentation

This directory contains documentation that is no longer current but is kept for historical reference.

## Archived Files

| File | Reason |
|------|--------|
| `ARCHITECTURE-REFACTORING.md` | Summary of the v1→v2 architecture changes. Work is complete. |
| `ARCHITECTURE_SEPARATION_ANALYSIS.md` | Analysis document for the architectural decision to separate pipeline processing from PDP server. Pipeline processing has been moved to [g119612/tsl-tool](https://github.com/sirosfoundation/g119612). |
| `CMD_TESTING_SUMMARY.md` | Test documentation for the old cmd package structure that included pipeline initialization. |
| `IMPROVEMENT_PLAN.md` | 8-week improvement plan for the old pipeline-based architecture. |
| `MIGRATION-TO-V2.md` | User-facing migration guide from v1 (pipeline+server) to v2 (server only). |
| `MOVING-TO-G119612.md` | Developer guide for moving pipeline code to g119612. Work is complete. |
| `PHASE2_COMPLETION_REPORT.md` | Completion report for Phase 2 improvements to the pipeline architecture. |
| `PHASE2_REVIEW.md` | Review of Phase 2 test improvements, focused on pipeline package coverage. |

## Current Architecture

Go-trust is now solely an AuthZEN Trust Decision Point (PDP) server. For TSL processing (load, transform, sign, publish), use `tsl-tool` from [g119612](https://github.com/sirosfoundation/g119612).

See the main [README](../../README.md) for current documentation.
