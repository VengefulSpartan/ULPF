import os
import time
import asyncio
from typing import Optional
import structlog

from ingest.ingester import IngestPipeline

logger = structlog.get_logger()


class FileTailer:
    """Asynchronously tails a local log file and ingests new raw lines losslessly."""

    def __init__(self, file_path: str, pipeline: IngestPipeline, poll_interval: float = 0.5):
        self.file_path = os.path.abspath(file_path)
        self.pipeline = pipeline
        self.poll_interval = poll_interval
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def _tail_loop(self) -> None:
        logger.info("file_tailer_started", file_path=self.file_path)
        
        while not os.path.exists(self.file_path) and self._running:
            await asyncio.sleep(self.poll_interval)

        if not self._running:
            return

        with open(self.file_path, "rb") as f:
            # Seek to end of file initially
            f.seek(0, os.SEEK_END)
            
            while self._running:
                line = f.readline()
                if line:
                    source_metadata = {
                        "protocol": "file_tailer",
                        "filename": os.path.basename(self.file_path),
                        "filepath": self.file_path
                    }
                    self.pipeline.process_raw_event(line, source_metadata)
                else:
                    await asyncio.sleep(self.poll_interval)

    def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._tail_loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            logger.info("file_tailer_stopped", file_path=self.file_path)
