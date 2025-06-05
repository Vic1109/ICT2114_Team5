#!/usr/bin/env python3
"""
Fixed Streaming SOC Log Processor with Gemini API
- Only processes NEW log entries (incremental processing)
- Detects new JSON files being added to directory
- Tracks file positions to avoid reprocessing
"""

import os
import time
import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Set
from google import genai
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class IncrementalLogProcessor:
    def __init__(self,
                 watch_directory: str,
                 output_dir: str,
                 api_key: str,
                 max_tokens: int = 800000,
                 model_name: str = "gemini-2.5-flash-preview-05-20"):

        self.watch_directory = Path(watch_directory).resolve()
        self.output_dir = Path(output_dir).resolve()
        self.api_key = api_key
        self.max_tokens = max_tokens
        self.model_name = model_name

        # Create directories
        self.watch_directory.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize Gemini client
        self.client = genai.Client(api_key=api_key)

        # Track file positions and processing state
        self.file_positions: Dict[str, int] = {}  # filename -> last read position
        self.chunk_counters: Dict[str, int] = {}  # filename -> chunk counter
        self.processing_files: Set[str] = set()  # currently processing files

        # Processing state
        self.chunk_buffer = ""
        self.current_file = None
        self.is_running = False
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Reserve tokens for system prompt and response overhead
        self.prompt_overhead = 2000
        self.usable_tokens = max_tokens - self.prompt_overhead

        print(f"🚀 Incremental SOC Log Processor Initialized")
        print(f"   📁 Watch Directory: {self.watch_directory}")
        print(f"   📂 Output Directory: {self.output_dir}")
        print(f"   🎯 Max tokens per chunk: {self.usable_tokens}")
        print(f"   🆔 Session ID: {self.session_id}")
        print(f"   🤖 Model: {self.model_name}")

    def count_tokens(self, text: str) -> int:
        """Count tokens using Gemini's official method"""
        try:
            token_count = self.client.models.count_tokens(
                model=self.model_name,
                contents=text
            )
            return token_count.total_tokens
        except Exception as e:
            print(f"⚠️  Error counting tokens: {e}")
            # Fallback: rough estimation (1 token ≈ 4 characters)
            return len(text) // 4

    def process_existing_files(self):
        """Process existing log files in the directory"""
        print(f"🔍 Scanning for existing log files...")

        log_files = list(self.watch_directory.glob("*.log")) + list(self.watch_directory.glob("*.json"))

        if log_files:
            print(f"📁 Found {len(log_files)} existing files to process")
            for file_path in log_files:
                self.process_file_incrementally(str(file_path), is_new_file=True)
        else:
            print(f"📭 No existing log files found")

    def process_file_incrementally(self, file_path: str, is_new_file: bool = False):
        """Process only new content from a file"""
        file_path = Path(file_path)
        filename = file_path.name

        if filename in self.processing_files:
            print(f"⏳ {filename} already being processed, skipping...")
            return

        self.processing_files.add(filename)

        try:
            if not file_path.exists():
                print(f"❌ File not found: {filename}")
                return

            # Get current file size
            current_size = file_path.stat().st_size

            # Get last known position for this file
            last_position = self.file_positions.get(filename, 0)

            # If it's a new file or file is smaller than last position (file was recreated)
            if is_new_file or current_size < last_position:
                last_position = 0
                self.chunk_counters[filename] = 1
                print(f"🆕 Processing new file: {filename}")
            else:
                print(f"📝 Processing new content in: {filename} (from position {last_position})")

            # If no new content
            if current_size <= last_position:
                print(f"✅ No new content in {filename}")
                return

            # Read only new content
            with open(file_path, 'r', encoding='utf-8') as f:
                f.seek(last_position)
                new_content = f.read()
                new_position = f.tell()

            if not new_content.strip():
                print(f"✅ No new meaningful content in {filename}")
                return

            print(f"📊 New content: {len(new_content)} characters")

            # Update file position
            self.file_positions[filename] = new_position

            # Process the new content
            self.process_content_chunks(new_content, filename)

        except Exception as e:
            print(f"❌ Error processing {filename}: {e}")
        finally:
            self.processing_files.discard(filename)

    def process_content_chunks(self, content: str, filename: str):
        """Process content in token-safe chunks"""
        if not filename in self.chunk_counters:
            self.chunk_counters[filename] = 1

        # Split content into log entries
        log_entries = self.parse_log_entries(content)

        if not log_entries:
            print(f"⚠️  No valid log entries found in new content")
            return

        print(f"📋 Found {len(log_entries)} new log entries")

        # Group entries into chunks that fit within token limits
        chunks = self.create_chunks(log_entries)

        print(f"🔢 Created {len(chunks)} chunks for processing")

        # Process each chunk
        for chunk_content in chunks:
            chunk_num = self.chunk_counters[filename]

            # Process chunk in background
            threading.Thread(
                target=self.analyze_and_save_chunk,
                args=(chunk_content, filename, chunk_num),
                daemon=True
            ).start()

            self.chunk_counters[filename] += 1

            # Small delay between chunks to avoid overwhelming the API
            time.sleep(0.5)

    def parse_log_entries(self, content: str) -> list:
        """Parse content into individual log entries"""
        entries = []
        lines = content.strip().split('\n')

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                # Try to parse as JSON
                entry = json.loads(line)
                entries.append(entry)
            except json.JSONDecodeError:
                # If not valid JSON, treat as raw text
                entries.append({"raw_log": line, "timestamp": datetime.now().isoformat()})

        return entries

    def create_chunks(self, log_entries: list) -> list:
        """Create chunks of log entries that fit within token limits"""
        chunks = []
        current_chunk = []
        current_tokens = 0

        for entry in log_entries:
            entry_text = json.dumps(entry, indent=2)
            entry_tokens = self.count_tokens(entry_text)

            # If single entry exceeds limit, truncate it
            if entry_tokens > self.usable_tokens:
                if current_chunk:
                    chunks.append(json.dumps(current_chunk, indent=2))
                    current_chunk = []
                    current_tokens = 0

                # Truncate the large entry
                truncated_entry = self.truncate_entry(entry, self.usable_tokens)
                chunks.append(json.dumps([truncated_entry], indent=2))
                continue

            # If adding this entry would exceed limit, start new chunk
            if current_tokens + entry_tokens > self.usable_tokens:
                if current_chunk:
                    chunks.append(json.dumps(current_chunk, indent=2))
                current_chunk = [entry]
                current_tokens = entry_tokens
            else:
                current_chunk.append(entry)
                current_tokens += entry_tokens

        # Add remaining entries
        if current_chunk:
            chunks.append(json.dumps(current_chunk, indent=2))

        return chunks

    def truncate_entry(self, entry: dict, max_tokens: int) -> dict:
        """Truncate a log entry to fit within token limits"""
        essential_fields = ["_id", "ident", "timestamp", "channel"]
        truncated = {}

        for field in essential_fields:
            if field in entry:
                truncated[field] = entry[field]

        # Handle payload truncation
        if "payload" in entry:
            payload_str = str(entry["payload"])
            remaining_tokens = max_tokens - self.count_tokens(json.dumps(truncated))

            if remaining_tokens > 100:
                max_payload_chars = remaining_tokens * 3
                if len(payload_str) > max_payload_chars:
                    truncated["payload"] = payload_str[:max_payload_chars] + "... [TRUNCATED]"
                else:
                    truncated["payload"] = payload_str
            else:
                truncated["payload"] = "[TRUNCATED - Too large]"

        return truncated

    def analyze_and_save_chunk(self, chunk_content: str, filename: str, chunk_num: int):
        """Analyze chunk with Gemini and save results"""
        try:
            print(f"🔍 Analyzing {filename} chunk {chunk_num}...")

            # Prepare the analysis prompt
            prompt = self.create_analysis_prompt(chunk_content, filename)

            # Count tokens for the prompt
            prompt_tokens = self.count_tokens(prompt)
            print(f"📊 {filename} chunk {chunk_num} - Prompt tokens: {prompt_tokens}")

            # Send to Gemini
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )

            analysis_result = response.text

            # Log token usage from response
            if hasattr(response, 'usage_metadata'):
                usage = response.usage_metadata
                print(f"📈 {filename} chunk {chunk_num} - Prompt: {usage.prompt_token_count}, "
                      f"Response: {usage.candidates_token_count}, "
                      f"Total: {usage.total_token_count}")

            # Save results
            output_file = self.save_analysis(chunk_content, analysis_result, filename, chunk_num)

            print(f"✅ {filename} chunk {chunk_num} processed and saved to: {output_file.name}")

        except Exception as e:
            error_msg = f"❌ Error processing {filename} chunk {chunk_num}: {str(e)}"
            print(error_msg)
            self.save_error(chunk_content, error_msg, filename, chunk_num)

    def create_analysis_prompt(self, chunk_content: str, filename: str) -> str:
        """Create the analysis prompt for Gemini"""
        return f"""
You are an expert SOC analyst. Analyze the following log data from file "{filename}" for security threats and provide:

## 🎯 THREAT SUMMARY
Brief overview of potential security threats detected in this chunk.

## 🔍 ATTACK PATTERNS & MITRE ATT&CK
Identify specific techniques from the MITRE ATT&CK framework:
- Tactic: [e.g., Initial Access, Execution, etc.]
- Technique: [e.g., T1190 - Exploit Public-Facing Application]
- Evidence: [What in the logs supports this]

## ⚠️ SUSPICIOUS ACTIVITIES
List specific concerning behaviors or indicators:
- Unusual network patterns
- Potential malicious payloads
- Anomalous user agents or requests
- Command injection attempts
- Other security concerns

## 📊 SEVERITY ASSESSMENT
Rate the overall threat level: **LOW** / **MEDIUM** / **HIGH**

Reasoning: [Brief explanation of severity rating]

## 🚨 IMMEDIATE RECOMMENDATIONS
Actionable steps for SOC team:
1. [Specific action item]
2. [Specific action item]
3. [Specific action item]

## 📋 LOG SUMMARY
- Source file: {filename}
- Total log entries in chunk: [count]
- Time range: [if determinable]
- Primary log sources: [channels/systems]

---
LOG DATA:
{chunk_content}
"""

    def save_analysis(self, chunk_content: str, analysis: str, filename: str, chunk_num: int) -> Path:
        """Save analysis results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        safe_filename = filename.replace('.', '_').replace('/', '_').replace('\\', '_')
        output_filename = f"{safe_filename}_chunk_{chunk_num:05d}_{timestamp}.txt"
        output_file = self.output_dir / output_filename

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"{'=' * 80}\n")
            f.write(f"SOC LOG ANALYSIS - {filename} CHUNK {chunk_num}\n")
            f.write(f"{'=' * 80}\n")
            f.write(f"Session ID: {self.session_id}\n")
            f.write(f"Source File: {filename}\n")
            f.write(f"Processed: {datetime.now().isoformat()}\n")
            f.write(f"Chunk Size: {len(chunk_content)} characters\n")
            f.write(f"Estimated Tokens: {self.count_tokens(chunk_content)}\n")
            f.write(f"{'=' * 80}\n\n")

            f.write("## ANALYSIS RESULTS\n\n")
            f.write(analysis)
            f.write(f"\n\n{'=' * 80}\n")
            f.write("## ORIGINAL LOG DATA\n\n")
            f.write(chunk_content)
            f.write(f"\n{'=' * 80}\n")

        return output_file

    def save_error(self, chunk_content: str, error_msg: str, filename: str, chunk_num: int):
        """Save error information when processing fails"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
        safe_filename = filename.replace('.', '_').replace('/', '_').replace('\\', '_')
        error_filename = f"error_{safe_filename}_chunk_{chunk_num:05d}_{timestamp}.txt"
        error_file = self.output_dir / error_filename

        with open(error_file, 'w', encoding='utf-8') as f:
            f.write(f"ERROR PROCESSING {filename} CHUNK {chunk_num}\n")
            f.write(f"{'=' * 50}\n")
            f.write(f"Error: {error_msg}\n")
            f.write(f"Time: {datetime.now().isoformat()}\n")
            f.write(f"{'=' * 50}\n\n")
            f.write("CHUNK CONTENT:\n")
            f.write(chunk_content)


class LogFileHandler(FileSystemEventHandler):
    """Handle file system events for log files"""

    def __init__(self, processor: IncrementalLogProcessor):
        self.processor = processor
        self.last_processed = {}  # filename -> last processed time

    def on_created(self, event):
        """Handle new file creation"""
        if event.is_directory:
            return

        file_path = event.src_path
        if file_path.endswith(('.log', '.json')):
            print(f"🆕 New file detected: {Path(file_path).name}")
            # Small delay to ensure file writing is complete
            time.sleep(1)
            self.processor.process_file_incrementally(file_path, is_new_file=True)

    def on_modified(self, event):
        """Handle file modifications (new content appended)"""
        if event.is_directory:
            return

        file_path = event.src_path
        if file_path.endswith(('.log', '.json')):
            filename = Path(file_path).name
            current_time = time.time()

            # Avoid processing the same file too frequently
            if filename in self.last_processed:
                if current_time - self.last_processed[filename] < 2:  # 2 second cooldown
                    return

            self.last_processed[filename] = current_time

            print(f"📝 File modified: {filename}")
            # Small delay to ensure file writing is complete
            time.sleep(1)
            self.processor.process_file_incrementally(file_path, is_new_file=False)


def main():
    """Main function with configuration"""

    # 🔧 CONFIGURATION
    project_root = Path(__file__).parent.resolve()

    CONFIG = {
        'WATCH_DIRECTORY': project_root / 'ICT2114_Team15' / 'logs',  # Directory to watch
        'OUTPUT_DIR': project_root / 'ICT2114_Team15' / 'report',  # Output directory
        'API_KEY': 'AIzaSyAwleKhZrh4lsOkaIV52Sav4Mn0nF5Q5bA',  # Your Gemini API key
        'MAX_TOKENS': 800000,  # Max tokens per chunk
        'MODEL_NAME': 'gemini-2.5-flash-preview-05-20'  # Gemini model to use
    }

    print("🚀 Incremental SOC Log Processor")
    print("=" * 50)
    print(f"📁 Watch Directory: {CONFIG['WATCH_DIRECTORY']}")
    print(f"📂 Output Directory: {CONFIG['OUTPUT_DIR']}")
    print()

    # Create processor
    processor = IncrementalLogProcessor(
        watch_directory=str(CONFIG['WATCH_DIRECTORY']),
        output_dir=str(CONFIG['OUTPUT_DIR']),
        api_key=CONFIG['API_KEY'],
        max_tokens=CONFIG['MAX_TOKENS'],
        model_name=CONFIG['MODEL_NAME']
    )

    # Process existing files first
    processor.process_existing_files()

    # Set up real-time monitoring
    event_handler = LogFileHandler(processor)
    observer = Observer()
    observer.schedule(event_handler, str(CONFIG['WATCH_DIRECTORY']), recursive=False)
    observer.start()

    processor.is_running = True

    try:
        print(f"\n🎬 Real-time monitoring started")
        print(f"👀 Watching: {CONFIG['WATCH_DIRECTORY']}")
        print(f"📤 Output: {CONFIG['OUTPUT_DIR']}")
        print(f"🛑 Press Ctrl+C to stop\n")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        observer.stop()
        processor.is_running = False
        print(f"\n🛑 Stopping incremental log processor...")

    observer.join()
    print(f"✅ Incremental log processor stopped")


if __name__ == "__main__":
    main()