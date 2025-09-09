import asyncio
import logging
from google.adk.agents import SequentialAgent, BaseAgent
from google.adk.events import Event
from google.genai.types import Content, Part
from .threat_analyzer import threat_analyzer

class Inspector(BaseAgent):
    async def _run_async_impl(self, context):
        logging.info("Starting inspector agent")
        seen_processes = set()
        while True:
            proc = await asyncio.create_subprocess_shell(
                "lsof -Pni -Fpuc",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if stdout:
                output = stdout.decode()
                processes = {}
                pid = None
                for line in output.strip().split("\n"):
                    if line.startswith("p"):
                        pid = line[1:]
                        processes[pid] = {"pid": pid}
                    elif line.startswith("u") and pid:
                        processes[pid]["user"] = line[1:]
                    elif line.startswith("c") and pid:
                        processes[pid]["command"] = line[1:]

                for pid, process_info in processes.items():
                    if pid not in seen_processes:
                        process_info_str = str(process_info)
                        context.session.state["process_info"] = process_info_str
                        yield Event(
                            author="inspector",
                            content=Content(parts=[Part(text=process_info_str)]),
                        )
                        seen_processes.add(pid)
            await asyncio.sleep(5)

inspector = Inspector(name="inspector")

from .remediation_tool import remediation_tool

inspector_agent = SequentialAgent(
    name="inspector_agent",
    description="Inspects network connections and analyzes for threats.",
    sub_agents=[inspector, threat_analyzer],
)
