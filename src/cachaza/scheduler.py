"""Conservative stage DAG: unproven dependencies remain ordered barriers."""
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
import time

from .network_policy import MAX_CONCURRENCY

# These stages read only TargetSpec and credentials, write disjoint artifacts,
# and use disjoint finding sources. Their requests all use the global limiter.
# Other stages include workspace readers, subprocesses or process-wide temporary
# credentials. Keep them as barriers until those side effects are isolated.
INDEPENDENT = frozenset({"corporate", "ct", "api"})


def dependencies(stages):
    return {i: {j for j in range(i) if name not in INDEPENDENT
                or stages[j] not in INDEPENDENT or name == stages[j]}
            for i, name in enumerate(stages)}


def execute_stages(pipeline, stage_map):
    stages = pipeline.options.stages
    jobs = max(1, min(pipeline.options.jobs, MAX_CONCURRENCY))
    if pipeline.workspace.resume or pipeline.options.strict or jobs == 1:
        for name in stages:
            pipeline._run_stage(name, stage_map[name])
        return
    dag = dependencies(stages)
    done = set()

    def collect(name):
        started = time.perf_counter()
        with pipeline.workspace.collect_stage() as findings:
            try:
                details, error = stage_map[name](), None
            except Exception as exc:
                details, error = None, exc
        return findings, details, error, time.perf_counter() - started

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        while len(done) < len(stages):
            ready = [i for i in dag if i not in done and dag[i] <= done][:jobs]
            if len(ready) == 1:
                i = ready[0]
                pipeline._run_stage(stages[i], stage_map[stages[i]])
                done.add(i)
                continue
            futures = [pool.submit(copy_context().run, collect, stages[i]) for i in ready]
            for i, future in zip(ready, futures):
                duration = None
                def commit():
                    nonlocal duration
                    findings, details, error, duration = future.result()
                    for finding in findings:
                        pipeline.workspace.add(finding)
                    if error is not None:
                        raise error
                    return details
                pipeline._run_stage(stages[i], commit)
                if duration is not None:
                    pipeline.run_cache.stage_seconds[stages[i]] = duration
                done.add(i)
