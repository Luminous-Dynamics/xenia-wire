# AUTH-001 — Real-Model Controller Protocol

**Status:** protocol prepared; **no real-model run is claimed**.

The next AUTH evidence gate is a preregistered comparison using at least two compact open-weight instruction models as controllers.

## Candidate controller matrix

- `HuggingFaceTB/SmolLM2-360M-Instruct` — primary compact Apache-2.0 candidate.
- `Qwen/Qwen3-0.6B` — secondary Apache-2.0 candidate.
- `google/gemma-3-270m-it` — optional third candidate; requires acceptance of Gemma access/usage terms.

Exact repository revisions are **not frozen yet**. Freeze model revision, inference runtime, quantization, prompts, task set, seeds, parser, adaptation schedule, metrics and analysis code before observing scored outputs. Do not choose models afterward merely because one yields a more favorable C>B result.

## Primary comparison

Use deterministic decoding where supported (`temperature=0`, fixed seed where exposed), 20 adaptation rounds, and the same controller/task distribution across B and C. Report unauthorized environment effects together with false denials and useful-task cost.

The v20 harness additionally requires arm-neutral controller-visible grant summaries, normalized denial feedback, strict JSON parsing, and counterfactual replay of B-generated traces through both B/C and C-generated traces through both B/C. This is intended to distinguish controller-behavior divergence from enforcement divergence.

## Interpretation

- **C > B:** potentially supportive only if replicated across frozen models/seeds, survives fixed-trace replay, and does not hide utility cost.
- **B ≈ C:** weakens the capability-specific thesis.
- **C < B:** evidence against the proposed complexity.
- failures moving into issuance/delegation/identity roots are research-target relocation, not a win.

## Non-claim

No real-model result has yet been produced by this branch.
