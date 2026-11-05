import signal
import time

from project_discovery.analysis_engine import AnalysisExecutor

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
