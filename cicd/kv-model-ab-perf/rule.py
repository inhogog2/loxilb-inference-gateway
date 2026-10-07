#!/usr/bin/env python3
"""rule.py exact|baseline|calibration <vip> <port> <engine> <model> <profile> <engine port> <prefills> <decodes> <topology>

Print the gateway rule of one arm, or of the calibration run (a baseline rule on one line).
The baseline rule has exact routing off. On a prefill/decode fleet the gateway still has to speak the engine's
prefill/decode dialect, which it picks from the rule's engine type: an SGLang fleet whose rule names no engine
type is driven the vLLM way and answers every request with an empty stream.
The exact rule's block size is the engine's: 16 tokens as vLLM and SGLang are launched, 32 on TensorRT-LLM.
"""
import json
import sys


def build(arm, vip, port, eng, model, prof, eport, pre, dec, topo):
    sa = {"externalIP": vip, "port": int(port), "protocol": "tcp", "sel": 0, "mode": 4, "host": vip, "probeRetries": 1,
          "sse_mode": True, "model_name": model, "kvExactMode": 0}
    if topo == "pd":
        sa["pd_disagg_mode"] = True
        if eng == "sglang":
            sa["kvEngineType"] = eng
    if arm == "exact":   # exact mode 1 = prefill/decode rule, 3 = converged (role-less endpoints)
        sa.update(kvExactMode=1 if topo == "pd" else 3, kvBlockSize=32 if eng == "trtllm" else 16, kvEngineType=eng,
                  kvExactApiMode="both", kvModelProfile=prof)
    if topo == "pd":
        eps = [{"endpointIP": n, "targetPort": int(eport), "weight": 1, "ep_role": 1} for n in pre.split()]
        eps += [{"endpointIP": n, "targetPort": int(eport), "weight": 1, "ep_role": 2} for n in dec.split()]
    else:
        eps = [{"endpointIP": n, "targetPort": int(eport), "weight": 1} for n in pre.split()]
    return {"serviceArguments": sa, "endpoints": eps}


def main():
    arm = sys.argv[1]
    if arm not in ("exact", "baseline", "calibration") or len(sys.argv) != 11:
        print(__doc__.splitlines()[0], file=sys.stderr)
        return 2
    print(json.dumps(build(*sys.argv[1:]), indent=None if arm == "calibration" else 1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
