"""Embedding memory recovery that also runs inside SentenceTransformers workers."""

import gc

from sentence_transformers import SentenceTransformer


class MemorySafeSentenceTransformer(SentenceTransformer):
    """Reduce inference batch size on CUDA OOM without changing the vectors' contract.

    SentenceTransformers' process worker calls ``model.encode``. Recovery belongs
    here: an OOM escaping that worker can otherwise leave its parent waiting for
    a result that will never arrive. Model, input text, sequence limit, precision,
    normalization and output order are unchanged by these retries.
    """

    def _get_model_type(self, *args, **kwargs):
        # SentenceTransformers 5.1.1 compares this result with the concrete
        # class name before choosing its saved-module loader. Our subclass must
        # still load the original dense model's saved pooling/configuration;
        # otherwise Qwen's last-token pooling could become auto-model pooling.
        model_type = super()._get_model_type(*args, **kwargs)
        return type(self).__name__ if model_type == "SentenceTransformer" else model_type

    def reset_memory_backoff(self):
        """Let a new build use VRAM that may have become available since the last."""
        self._memory_safe_batch_sizes = {}
        self._memory_cpu_fallback_devices = set()

    @staticmethod
    def _is_cuda_oom(error, device):
        if not str(device).startswith("cuda"):
            return False
        message = str(error).lower()
        return type(error).__name__ == "OutOfMemoryError" or any(
            marker in message for marker in (
                "cuda out of memory", "cuda error: out of memory",
                "cublas_status_alloc_failed",
            )
        )

    @staticmethod
    def _clear_cuda_cache(device):
        # Call outside the except block, after the failed forward's traceback
        # and its live tensors have been released.
        gc.collect()
        try:
            import torch
            with torch.cuda.device(device):
                torch.cuda.empty_cache()
        except Exception:
            pass

    def encode(self, sentences, *, batch_size=32, device=None, **kwargs):
        # A pool dispatcher allocates no inference tensors. Each actual worker
        # re-enters this override with a single explicit device.
        if kwargs.get("pool") is not None or isinstance(device, (list, tuple)):
            return super().encode(
                sentences, batch_size=batch_size, device=device, **kwargs
            )

        requested_device = str(device if device is not None else self.device)
        safe_batches = getattr(self, "_memory_safe_batch_sizes", None)
        if safe_batches is None:
            self._memory_safe_batch_sizes = safe_batches = {}
        cpu_devices = getattr(self, "_memory_cpu_fallback_devices", None)
        if cpu_devices is None:
            self._memory_cpu_fallback_devices = cpu_devices = set()
        target = "cpu" if requested_device in cpu_devices else requested_device
        count = 1 if isinstance(sentences, str) else max(1, len(sentences))
        current_batch = min(max(1, int(batch_size)), count)
        current_batch = min(current_batch, safe_batches.get(target, current_batch))

        while True:
            try:
                return super().encode(
                    sentences, batch_size=current_batch, device=target, **kwargs
                )
            except Exception as error:
                if not self._is_cuda_oom(error, target):
                    raise
            self._clear_cuda_cache(target)
            if current_batch > 1:
                current_batch = max(1, current_batch // 2)
                safe_batches[target] = current_batch
                print(f"Embedding CUDA memory pressure on {target}; retrying with batch={current_batch}")
                continue

            # Shared VRAM (for example an already loaded llama.cpp model) can
            # leave too little room even for one input. Keep this worker on CPU
            # for subsequent work instead of repeatedly attempting a full GPU.
            cpu_devices.add(requested_device)
            self.to("cpu")
            self._clear_cuda_cache(target)
            target = "cpu"
            print(f"Embedding CUDA memory pressure on {requested_device}; retrying on CPU")
