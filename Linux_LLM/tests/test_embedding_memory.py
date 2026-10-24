"""Memory recovery regressions; fake encoders require no model, GPU or database."""

import ast
import gc
import json
import math
import sys
import unittest
from pathlib import Path
from queue import Empty
from types import SimpleNamespace
from typing import Any, List
from unittest import mock


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"


def _runtime_class():
    # Load the production class against a fake base without importing PyTorch or
    # SentenceTransformers. This checks its actual retry code, not a test copy.
    tree = ast.parse((CONFIG_DIR / "embedding_runtime.py").read_text(encoding="utf-8"))
    definition = next(node for node in tree.body if isinstance(node, ast.ClassDef))

    class FakeEncoder:
        def __init__(self):
            self.device = "cpu"
            self.calls = []
            self.moves = []
            self.behavior = lambda texts, **kwargs: [[text] for text in texts]

        def encode(self, texts, **kwargs):
            self.calls.append((texts, kwargs))
            return self.behavior(texts, **kwargs)

        def to(self, device):
            self.moves.append(device)
            self.device = device
            return self

        def _get_model_type(self, *args, **kwargs):
            return kwargs.get("stored_type", "SentenceTransformer")

    namespace = {"SentenceTransformer": FakeEncoder, "gc": gc}
    exec(compile(ast.Module(body=[definition], type_ignores=[]), "embedding_runtime.py", "exec"), namespace)
    return namespace[definition.name]


class EmbeddingMemoryRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.model = _runtime_class()()
        self.cache_cleanup = mock.patch.object(self.model, "_clear_cuda_cache")
        self.cache_cleanup.start()
        self.addCleanup(self.cache_cleanup.stop)

    def test_dense_saved_modules_keep_the_original_pooling_loader(self):
        self.assertEqual(self.model._get_model_type("configured/model"), type(self.model).__name__)
        self.assertEqual(self.model._get_model_type("configured/model", stored_type="SparseEncoder"), "SparseEncoder")

    def test_worker_halves_batch_and_preserves_all_inputs_and_options(self):
        texts = [f"evidence {index}" for index in range(8)]

        def encode(texts, **kwargs):
            if kwargs["batch_size"] > 2:
                raise RuntimeError("CUDA out of memory")
            return [[text] for text in texts]

        self.model.behavior = encode
        result = self.model.encode(
            texts, batch_size=8, device="cuda:1", normalize_embeddings=True,
            precision="float32", show_progress_bar=False,
        )
        self.assertEqual(result, [[text] for text in texts])
        self.assertEqual([call[1]["batch_size"] for call in self.model.calls], [8, 4, 2])
        for actual_texts, kwargs in self.model.calls:
            self.assertIs(actual_texts, texts)
            self.assertEqual(kwargs["device"], "cuda:1")
            self.assertTrue(kwargs["normalize_embeddings"])
            self.assertEqual(kwargs["precision"], "float32")
        self.model.encode(texts, batch_size=8, device="cuda:1")
        self.assertEqual(self.model.calls[-1][1]["batch_size"], 2)

    def test_singleton_oom_falls_back_and_worker_stays_on_cpu_for_the_build(self):
        def encode(texts, **kwargs):
            if kwargs["device"].startswith("cuda"):
                raise RuntimeError("CUDA out of memory")
            return [[text] for text in texts]

        self.model.behavior = encode
        self.assertEqual(self.model.encode(["original"], device="cuda:0"), [["original"]])
        self.assertEqual(self.model.moves, ["cpu"])
        self.model.encode(["next"], device="cuda:0")
        self.assertEqual([call[1]["device"] for call in self.model.calls], ["cuda:0", "cpu", "cpu"])
        self.model.reset_memory_backoff()
        self.model.encode(["new build"], device="cuda:0")
        self.assertEqual([call[1]["device"] for call in self.model.calls[-2:]], ["cuda:0", "cpu"])

    def test_unrelated_and_cpu_failures_propagate_without_retry(self):
        for device, failure in (("cuda:0", ValueError("bad dimensions")), ("cpu", MemoryError("host exhausted"))):
            self.model.calls.clear()
            self.model.behavior = mock.Mock(side_effect=failure)
            with self.assertRaises(type(failure)):
                self.model.encode(["original"], device=device)
            self.assertEqual(len(self.model.calls), 1)
        self.model._clear_cuda_cache.assert_not_called()

    def test_parent_pool_dispatch_is_unchanged_for_worker_local_recovery(self):
        pool = {"processes": ["one", "two"]}
        self.model.encode(["original"], pool=pool, batch_size=8, normalize_embeddings=True)
        self.assertIs(self.model.calls[0][1]["pool"], pool)
        self.assertEqual(self.model.calls[0][1]["batch_size"], 8)
        self.assertEqual(self.model.moves, [])

    def test_cuda_cache_cleanup_selects_the_failed_device(self):
        runtime = _runtime_class()
        cuda = SimpleNamespace(device=mock.MagicMock(), empty_cache=mock.Mock())
        with mock.patch.dict(sys.modules, {"torch": SimpleNamespace(cuda=cuda)}):
            runtime._clear_cuda_cache("cuda:2")
        cuda.device.assert_called_once_with("cuda:2")
        cuda.empty_cache.assert_called_once_with()


def _scheduling_manager():
    # Only parse the scheduling methods; no application imports or resources.
    tree = ast.parse((CONFIG_DIR / "report.py").read_text(encoding="utf-8"))
    manager = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "RAGContextManager")
    methods = {
        "_commit_embedding_batches", "_commit_encoded_groups", "_partition_embedding_pairs",
        "_should_use_multi_gpu_encoding", "_pairs_from_stored_rows", "_encode_with_pool",
    }
    definition = ast.ClassDef(
        name="SchedulingManager", bases=[], keywords=[],
        body=[node for node in manager.body if isinstance(node, ast.FunctionDef) and node.name in methods],
        decorator_list=[],
    )
    module = ast.fix_missing_locations(ast.Module(body=[definition], type_ignores=[]))
    namespace = {
        "List": List, "Any": Any, "json": json, "math": math,
        "limit_blas_threads_for_workers": mock.Mock(return_value={"saved": "value"}),
        "restore_blas_thread_env": mock.Mock(), "log_sanitized_exception": mock.Mock(),
    }
    exec(compile(module, "report.py", "exec"), namespace)
    result = namespace["SchedulingManager"]()
    result.embedding_batch_size = 32
    result.normalize_embeddings = True
    result.embedding_devices = ["cuda:0", "cuda:1"]
    result.embedding_multi_gpu_min_chunks = 2
    result.embeddings = mock.Mock()
    result._prepare_embedding_inputs = lambda texts, is_query=False: list(texts)
    result._encode_with_pool = mock.Mock(side_effect=lambda texts, pool, batch: [[text] for text in texts])
    result._encode_texts = mock.Mock(side_effect=lambda texts, **kwargs: [[text] for text in texts])
    result._encode_on_bulk_device = mock.Mock(side_effect=lambda texts, batch: [[text] for text in texts])
    result._write_embedding_rows = mock.Mock()
    result._release_embedding_device = mock.Mock()
    result._as_embedding_rows = list
    return result, namespace


class EmbeddingSchedulingTests(unittest.TestCase):
    def test_four_gpu_commit_fills_configured_batches_and_preserves_order(self):
        manager, _namespace = _scheduling_manager()
        texts = [f"body {index}" for index in range(256)]
        workers = [SimpleNamespace(is_alive=mock.Mock(return_value=True)) for _index in range(4)]
        pool = {"processes": workers, "input": mock.Mock(), "output": mock.Mock()}
        pool["output"].get.side_effect = [
            (index, [[text] for text in texts[index * 32:(index + 1) * 32]])
            for index in reversed(range(8))
        ]
        result = type(manager)._encode_with_pool(manager, texts, pool, batch_size=32)
        self.assertEqual(result, [[text] for text in texts])
        self.assertEqual(len(pool["input"].put.call_args_list), 8)
        self.assertEqual([len(call.args[0][1]) for call in pool["input"].put.call_args_list], [32] * 8)

    def test_pool_reorders_finished_chunks_and_checks_worker_liveness(self):
        manager, _namespace = _scheduling_manager()
        workers = [SimpleNamespace(is_alive=mock.Mock(return_value=True)) for _index in range(2)]
        pool = {"processes": workers, "input": mock.Mock(), "output": mock.Mock()}
        pool["output"].get.side_effect = [Empty(), (1, [["two"]]), (0, [["one"]])]
        result = type(manager)._encode_with_pool(manager, ["one", "two"], pool, batch_size=8)
        self.assertEqual(result, [["one"], ["two"]])
        for worker in workers:
            worker.is_alive.assert_called_once_with()
        for call in pool["input"].put.call_args_list:
            self.assertEqual(call.args[0][2]["batch_size"], 8)
            self.assertTrue(call.args[0][2]["normalize_embeddings"])

    def test_dead_worker_raises_instead_of_waiting_forever(self):
        manager, _namespace = _scheduling_manager()
        worker = SimpleNamespace(is_alive=mock.Mock(return_value=False))
        pool = {"processes": [worker], "input": mock.Mock(), "output": mock.Mock()}
        pool["output"].get.side_effect = Empty()
        with self.assertRaisesRegex(RuntimeError, "worker exited"):
            type(manager)._encode_with_pool(manager, ["one"], pool, batch_size=8)

    def test_long_and_short_rows_share_one_pool_and_keep_row_vector_association(self):
        manager, _namespace = _scheduling_manager()
        pairs = [(1, "short"), (2, "long " * 500), (3, "short again")]
        manager._commit_embedding_batches("custom_documents", pairs)
        manager.embeddings.start_multi_process_pool.assert_called_once_with(manager.embedding_devices)
        self.assertEqual([call.args[2] for call in manager._encode_with_pool.call_args_list], [8, 32])
        for call in manager._write_embedding_rows.call_args_list:
            _table, rows, vectors = call.args
            self.assertEqual(vectors, [[text] for _id, text in rows])
        manager.embeddings.stop_multi_process_pool.assert_called_once()
        manager._release_embedding_device.assert_called_once()

    def test_cpu_path_honors_reduced_long_batch(self):
        manager, _namespace = _scheduling_manager()
        manager.embedding_devices = []
        manager._commit_embedding_batches("custom_documents", [(1, "long " * 500)])
        manager._encode_texts.assert_called_once_with(["long " * 500], is_query=False, batch_size=8)

    def test_failure_keeps_finished_commit_and_always_stops_workers(self):
        manager, namespace = _scheduling_manager()
        manager.EMBEDDING_COMMIT_ROWS = 1
        manager._encode_with_pool.side_effect = [[["one"]], ValueError("invalid vector")]
        with self.assertRaisesRegex(ValueError, "invalid vector"):
            manager._commit_embedding_batches("custom_documents", [(1, "one"), (2, "two")])
        self.assertEqual(manager._write_embedding_rows.call_count, 1)
        manager.embeddings.stop_multi_process_pool.assert_called_once()
        namespace["restore_blas_thread_env"].assert_called_once_with({"saved": "value"})

    def test_resumed_rows_embed_the_same_body_as_fresh_rows(self):
        manager, _namespace = _scheduling_manager()
        rows = [
            (1, "header\nbody", {"embedding_body_offset": 7}),
            (2, "header\nbody2", json.dumps({"embedding_body_offset": 7})),
        ]
        self.assertEqual(manager._pairs_from_stored_rows(rows), [(1, "body"), (2, "body2")])


if __name__ == "__main__":
    unittest.main()
