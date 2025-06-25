# Security Operations Center - Threat Analysis Report

**Report Generated:** 2025-06-26 01:12:10  
**Analysis Period:** 2025-06-25 to 2025-06-26 (daily)  
**Total Alerts Analyzed:** 500  
**Report Type:** Comprehensive  
**Wazuh Server:** 100.78.175.127

---

Error: Llama.cpp process failed.
Stderr: ggml_cuda_init: GGML_CUDA_FORCE_MMQ:    no
ggml_cuda_init: GGML_CUDA_FORCE_CUBLAS: no
ggml_cuda_init: found 1 CUDA devices:
  Device 0: NVIDIA GeForce GTX 1060, compute capability 6.1, VMM: yes
build: 5712 (9eaa51e7) with cc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0 for x86_64-linux-gnu
main: llama backend init
main: load the model and apply lora adapter, if any
llama_model_load_from_file_impl: using device CUDA0 (NVIDIA GeForce GTX 1060) - 5932 MiB free
llama_model_loader: loaded meta data with 32 key-value pairs and 398 tensors from /home/itp15student/Desktop/Qwen3-4B-Q4_K_M.gguf (version GGUF V3 (latest))
llama_model_loader: Dumping metadata keys/values. Note: KV overrides do not apply in this output.
llama_model_loader: - kv   0:                       general.architecture str              = qwen3
llama_model_loader: - kv   1:                               general.type str              = model
llama_model_loader: - kv   2:                               general.name str              = Qwen3-4B
llama_model_loader: - kv   3:                           general.basename str              = Qwen3-4B
llama_model_loader: - kv   4:                       general.quantized_by str              = Unsloth
llama_model_loader: - kv   5:                         general.size_label str              = 4B
llama_model_loader: - kv   6:                           general.repo_url str              = https://huggingface.co/unsloth
llama_model_loader: - kv   7:                          qwen3.block_count u32              = 36
llama_model_loader: - kv   8:                       qwen3.context_length u32              = 40960
llama_model_loader: - kv   9:                     qwen3.embedding_length u32              = 2560
llama_model_loader: - kv  10:                  qwen3.feed_forward_length u32              = 9728
llama_model_loader: - kv  11:                 qwen3.attention.head_count u32              = 32
llama_model_loader: - kv  12:              qwen3.attention.head_count_kv u32              = 8
llama_model_loader: - kv  13:                       qwen3.rope.freq_base f32              = 1000000.000000
llama_model_loader: - kv  14:     qwen3.attention.layer_norm_rms_epsilon f32              = 0.000001
llama_model_loader: - kv  15:                 qwen3.attention.key_length u32              = 128
llama_model_loader: - kv  16:               qwen3.attention.value_length u32              = 128
llama_model_loader: - kv  17:                       tokenizer.ggml.model str              = gpt2
llama_model_loader: - kv  18:                         tokenizer.ggml.pre str              = qwen2
llama_model_loader: - kv  19:                      tokenizer.ggml.tokens arr[str,151936]  = ["!", "\"", "#", "$", "%", "&", "'", ...
llama_model_loader: - kv  20:                  tokenizer.ggml.token_type arr[i32,151936]  = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, ...
llama_model_loader: - kv  21:                      tokenizer.ggml.merges arr[str,151387]  = ["Ġ Ġ", "ĠĠ ĠĠ", "i n", "Ġ t",...
llama_model_loader: - kv  22:                tokenizer.ggml.eos_token_id u32              = 151645
llama_model_loader: - kv  23:            tokenizer.ggml.padding_token_id u32              = 151654
llama_model_loader: - kv  24:               tokenizer.ggml.add_bos_token bool             = false
llama_model_loader: - kv  25:                    tokenizer.chat_template str              = {%- if tools %}\n    {{- '<|im_start|>...
llama_model_loader: - kv  26:               general.quantization_version u32              = 2
llama_model_loader: - kv  27:                          general.file_type u32              = 15
llama_model_loader: - kv  28:                      quantize.imatrix.file str              = Qwen3-4B-GGUF/imatrix_unsloth.dat
llama_model_loader: - kv  29:                   quantize.imatrix.dataset str              = unsloth_calibration_Qwen3-4B.txt
llama_model_loader: - kv  30:             quantize.imatrix.entries_count i32              = 252
llama_model_loader: - kv  31:              quantize.imatrix.chunks_count i32              = 685
llama_model_loader: - type  f32:  145 tensors
llama_model_loader: - type q4_K:  216 tensors
llama_model_loader: - type q6_K:   37 tensors
print_info: file format = GGUF V3 (latest)
print_info: file type   = Q4_K - Medium
print_info: file size   = 2.32 GiB (4.95 BPW) 
load: special tokens cache size = 26
load: token to piece cache size = 0.9311 MB
print_info: arch             = qwen3
print_info: vocab_only       = 0
print_info: n_ctx_train      = 40960
print_info: n_embd           = 2560
print_info: n_layer          = 36
print_info: n_head           = 32
print_info: n_head_kv        = 8
print_info: n_rot            = 128
print_info: n_swa            = 0
print_info: is_swa_any       = 0
print_info: n_embd_head_k    = 128
print_info: n_embd_head_v    = 128
print_info: n_gqa            = 4
print_info: n_embd_k_gqa     = 1024
print_info: n_embd_v_gqa     = 1024
print_info: f_norm_eps       = 0.0e+00
print_info: f_norm_rms_eps   = 1.0e-06
print_info: f_clamp_kqv      = 0.0e+00
print_info: f_max_alibi_bias = 0.0e+00
print_info: f_logit_scale    = 0.0e+00
print_info: f_attn_scale     = 0.0e+00
print_info: n_ff             = 9728
print_info: n_expert         = 0
print_info: n_expert_used    = 0
print_info: causal attn      = 1
print_info: pooling type     = 0
print_info: rope type        = 2
print_info: rope scaling     = linear
print_info: freq_base_train  = 1000000.0
print_info: freq_scale_train = 1
print_info: n_ctx_orig_yarn  = 40960
print_info: rope_finetuned   = unknown
print_info: ssm_d_conv       = 0
print_info: ssm_d_inner      = 0
print_info: ssm_d_state      = 0
print_info: ssm_dt_rank      = 0
print_info: ssm_dt_b_c_rms   = 0
print_info: model type       = 4B
print_info: model params     = 4.02 B
print_info: general.name     = Qwen3-4B
print_info: vocab type       = BPE
print_info: n_vocab          = 151936
print_info: n_merges         = 151387
print_info: BOS token        = 11 ','
print_info: EOS token        = 151645 '<|im_end|>'
print_info: EOT token        = 151645 '<|im_end|>'
print_info: PAD token        = 151654 '<|vision_pad|>'
print_info: LF token         = 198 'Ċ'
print_info: FIM PRE token    = 151659 '<|fim_prefix|>'
print_info: FIM SUF token    = 151661 '<|fim_suffix|>'
print_info: FIM MID token    = 151660 '<|fim_middle|>'
print_info: FIM PAD token    = 151662 '<|fim_pad|>'
print_info: FIM REP token    = 151663 '<|repo_name|>'
print_info: FIM SEP token    = 151664 '<|file_sep|>'
print_info: EOG token        = 151643 '<|endoftext|>'
print_info: EOG token        = 151645 '<|im_end|>'
print_info: EOG token        = 151662 '<|fim_pad|>'
print_info: EOG token        = 151663 '<|repo_name|>'
print_info: EOG token        = 151664 '<|file_sep|>'
print_info: max token length = 256
load_tensors: loading model tensors, this can take a while... (mmap = true)
load_tensors: offloading 36 repeating layers to GPU
load_tensors: offloading output layer to GPU
load_tensors: offloaded 37/37 layers to GPU
load_tensors:        CUDA0 model buffer size =  2375.91 MiB
load_tensors:   CPU_Mapped model buffer size =   304.28 MiB
...............................................................................
llama_context: constructing llama_context
llama_context: n_seq_max     = 1
llama_context: n_ctx         = 8192
llama_context: n_ctx_per_seq = 8192
llama_context: n_batch       = 2048
llama_context: n_ubatch      = 512
llama_context: causal_attn   = 1
llama_context: flash_attn    = 0
llama_context: freq_base     = 1000000.0
llama_context: freq_scale    = 1
llama_context: n_ctx_per_seq (8192) < n_ctx_train (40960) -- the full capacity of the model will not be utilized
llama_context:  CUDA_Host  output buffer size =     0.58 MiB
llama_kv_cache_unified:      CUDA0 KV buffer size =  1152.00 MiB
llama_kv_cache_unified: size = 1152.00 MiB (  8192 cells,  36 layers,  1 seqs), K (f16):  576.00 MiB, V (f16):  576.00 MiB
llama_context:      CUDA0 compute buffer size =   554.00 MiB
llama_context:  CUDA_Host compute buffer size =    21.01 MiB
llama_context: graph nodes  = 1446
llama_context: graph splits = 2
common_init_from_params: setting dry_penalty_last_n to ctx_size = 8192
common_init_from_params: warming up the model with an empty run - please wait ... (--no-warmup to disable)
main: llama threadpool init, n_threads = 6
main: chat template is available, enabling conversation mode (disable it with -no-cnv)
*** User-specified prompt will pre-start conversation, did you mean to set --system-prompt (-sys) instead?
main: chat template example:
<|im_start|>system
You are a helpful assistant<|im_end|>
<|im_start|>user
Hello<|im_end|>
<|im_start|>assistant
Hi there<|im_end|>
<|im_start|>user
How are you?<|im_end|>
<|im_start|>assistant


system_info: n_threads = 6 (n_threads_batch = 6) / 12 | CUDA : ARCHS = 610 | USE_GRAPHS = 1 | PEER_MAX_BATCH_SIZE = 128 | CPU : SSE3 = 1 | SSSE3 = 1 | AVX = 1 | AVX2 = 1 | F16C = 1 | FMA = 1 | BMI2 = 1 | LLAMAFILE = 1 | OPENMP = 1 | REPACK = 1 | 

main: interactive mode on.
sampler seed: 2925680683
sampler params: 
	repeat_last_n = 64, repeat_penalty = 1.000, frequency_penalty = 0.000, presence_penalty = 0.000
	dry_multiplier = 0.000, dry_base = 1.750, dry_allowed_length = 2, dry_penalty_last_n = 8192
	top_k = 40, top_p = 0.900, min_p = 0.050, xtc_probability = 0.000, xtc_threshold = 0.100, typical_p = 1.000, top_n_sigma = -1.000, temp = 0.700
	mirostat = 0, mirostat_lr = 0.100, mirostat_ent = 5.000
sampler chain: logits -> logit-bias -> penalties -> dry -> top-n-sigma -> top-k -> typical -> top-p -> min-p -> xtc -> temp-ext -> dist 
generate: n_ctx = 8192, n_batch = 2048, n_predict = 4096, n_keep = 0

== Running in interactive mode. ==
 - Press Ctrl+C to interject at any time.
 - Press Return to return control to the AI.
 - To return control without starting a new line, end your input with '/'.
 - If you want to submit another line, end your input with '\'.
 - Not using system message. To change it, set a different value via -sys PROMPT

llama_perf_sampler_print:    sampling time =     299.61 ms /  2877 runs   (    0.10 ms per token,  9602.42 tokens per second)
llama_perf_context_print:        load time =     797.15 ms
llama_perf_context_print: prompt eval time =     956.01 ms /   493 tokens (    1.94 ms per token,   515.69 tokens per second)
llama_perf_context_print:        eval time =  133708.54 ms /  2383 runs   (   56.11 ms per token,    17.82 tokens per second)
llama_perf_context_print:       total time =  248932.51 ms /  2876 tokens
