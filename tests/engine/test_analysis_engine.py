import signal
import time

from project_discovery.engine.executor import AnalysisExecutor

_STARTUP_TIMEOUT = 120  # spawning a worker imports every analyzer; CI runners can be slow


def test_process_workers_leave_ctrl_c_to_the_coordinator():
    executor = AnalysisExecutor("process", 1, [], file_count=0)
    try:
        handler = executor._pool.submit(signal.getsignal, signal.SIGINT).result(_STARTUP_TIMEOUT)
        assert handler == signal.SIG_IGN
    finally:
        executor.shutdown()


def test_cancelled_process_pool_stops_running_batches_promptly():
    executor = AnalysisExecutor("process", 1, [], file_count=0)
    executor._pool.submit(int).result(_STARTUP_TIMEOUT)  # the worker is up
    workers = list(executor._pool._processes.values())
    long_batch = executor._pool.submit(time.sleep, 120)
    time.sleep(0.5)

    started = time.monotonic()
    executor.shutdown(cancel=True)
    assert time.monotonic() - started < 30  # not the 120 s the running batch needs

    deadline = time.monotonic() + 30
    while any(worker.is_alive() for worker in workers) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not any(worker.is_alive() for worker in workers)
    assert long_batch.cancelled() or long_batch.exception(timeout=30) is not None


def test_thread_executor_cancel_keeps_waiting_semantics():
    executor = AnalysisExecutor("thread", 1, [], file_count=0)
    future = executor._pool.submit(time.sleep, 0.2)
    executor.shutdown(cancel=True)
    assert future.done()


def test_a_pool_that_refuses_work_is_replaced_once_and_the_batch_queued_again():
    # Regression (CI on Linux): a worker death noticed before the next batch was queued
    # made pool.submit() itself raise BrokenProcessPool, which escaped the scan.
    from concurrent.futures import Future
    from concurrent.futures.process import BrokenProcessPool

    class Pool:
        def __init__(self, broken):
            self.broken, self.shut = broken, False

        def submit(self, function, *arguments):
            if self.broken:
                raise BrokenProcessPool("A child process terminated abruptly")
            future = Future()
            future.set_result(function.__name__)
            return future

        def shutdown(self, wait=True, cancel_futures=False):
            self.shut = True

    engine = AnalysisExecutor("thread", 1, [], file_count=1)
    engine._pool.shutdown()
    broken = engine._pool = Pool(broken=True)
    pools = []
    engine._create_pool = lambda: pools.append(Pool(broken=False)) or pools[-1]
    future = engine.submit([])
    assert future.result() == "analyze_tasks"
    assert broken.shut and len(pools) == 1 and future.pdt_pool is pools[0]
    # A future of the replaced pool reporting the same breakage restarts nothing.
    stale = Future()
    stale.pdt_pool = broken
    engine.restart(stale)
    assert len(pools) == 1


def test_gpu_counters_of_worker_processes_reach_the_scan_metrics(monkeypatch):
    # Regression: the native GPU counters are per process, and only the coordinator's were
    # reported, so process-mode scans always showed 0 dispatches and 0 fallbacks.
    import project_discovery.engine.executor as executor
    from project_discovery.cli import _with_worker_gpu

    readings = iter([(3, 1), (7, 2)])
    monkeypatch.setattr(executor, "_gpu_counters", lambda: next(readings))
    monkeypatch.setitem(executor._worker_state, "analyzers", [])
    outcomes = executor._analyze_batch_in_worker([])
    assert outcomes == []          # no outcome to carry the delta: nothing to report
    readings = iter([(3, 1), (7, 2)])
    monkeypatch.setattr(executor, "_gpu_counters", lambda: next(readings))
    monkeypatch.setattr(executor, "analyze_tasks", lambda *_args: [executor.FileOutcome(), executor.FileOutcome()])
    outcomes = executor._analyze_batch_in_worker([object(), object()])
    assert outcomes[0].gpu_counts is None and outcomes[-1].gpu_counts == (4, 1)
    merged = _with_worker_gpu({"gpu_dispatches": 1, "gpu_fallbacks": 0, "backend": "c"}, [4, 1])
    assert (merged["gpu_dispatches"], merged["gpu_fallbacks"], merged["backend"]) == (5, 1, "c")
