import asyncio
import ast
from inspector_agent.agent import inspector_agent
from google.adk.runners import InMemoryRunner
from google.genai.types import Content, Part
from google.adk.events.event import Event
from google.adk.agents.process_analyzer import Threat

async def main():
    runner = InMemoryRunner(agent=inspector_agent, app_name="inspector_agent")
    await runner.session_service.create_session(
        app_name="inspector_agent", user_id="user", session_id="session"
    )
    async for event in runner.run_async(
            user_id="user",
            session_id="session",
            new_message=Content(parts=[Part(text="start")]),
        ):
            if isinstance(event, Event):
                event_text = event.description.parts[0].text
                event_data = ast.literal_eval(event_text)
                pid = event_data.get('pid')
                command = event_data.get('command')
                user = event_data.get('user')
                print(
                    "Process Detected: "
                    f"(PID: {pid}, Command: {command}, User: {user})"
                )
            elif isinstance(event, Threat):
                threat_text = event.description.parts[0].text
                threat_data = ast.literal_eval(threat_text)
                pid = threat_data.get('pid')
                command = threat_data.get('command')
                user = threat_data.get('user')
                print(
                    "Threat Detected: Suspicious process found "
                    f"(PID: {pid}, Command: {command}, User: {user})"
                )

if __name__ == "__main__":
    asyncio.run(main())
