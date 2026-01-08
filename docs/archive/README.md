# Archived Documentation

This directory contains documentation that is no longer current but is kept for historical reference.

## Archived Files

| File | Reason |
|------|--------|
| `ARCHITECTURE_SEPARATION_ANALYSIS.md` | Analysis document for the architectural decision to separate pipeline processing from PDP server. Pipeline processing has been moved to [g119612/tsl-tool](https://github.com/sirosfoundation/g119612). |
| `CMD_TESTING_SUMMARY.md` | Test documentation for the old cmd package structure that included pipeline initialization. |
| `IMPROVEMENT_PLAN.md` | 8-week improvement plan for the old pipeline-based architecture. |
| `PHASE2_COMPLETION_REPORT.md` | Completion report for Phase 2 improvements to the pipeline architecture. |
| `PHASE2_REVIEW.md` | Review of Phase 2 test improvements, focused on pipeline package coverage. |

## Current Architecture

Go-trust is now solely an AuthZEN Trust Decision Point (PDP) server. For TSL processing (load, transform, sign, publish), use `tsl-tool` from [g119612](https://github.com/sirosfoundation/g119612).

See the main [README](../../README.md) for current documentation.
