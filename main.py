import asyncio
from inspector_agent.agent import inspector_agent
from google.adk.runners import InMemoryRunner
from google.genai.types import Content, Part

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
            print(event)

if __name__ == "__main__":
    asyncio.run(main())
