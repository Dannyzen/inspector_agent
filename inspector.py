import asyncio
import logging
from threat_analyzer import ThreatAnalyzer

logging.basicConfig(level=logging.INFO)

async def main():
    """
    This is the main entry point for the application.
    It runs the inspector agent.
    """
    analyzer = ThreatAnalyzer()
    logging.info("Starting inspector")

    # Hardcoded threat simulation for demonstration
    pid = "429370"
    full_command = "nc -l 12345"
    user = "danny"
    port = "12345"

    analysis = analyzer.analyze(full_command, port)

    if analysis["is_threat"]:
        logging.warning("--- POTENTIAL THREAT DETECTED ---")
        logging.warning(f"  PID: {pid}, Command: '{full_command}', User: {user}")
        logging.warning(f"  Process Explanation: {analysis['process_explanation']}")
        logging.warning(f"  Rationale: {analysis['rationale']}")
        logging.warning("---------------------------------")
    else:
        logging.info(f"Found new listening process: PID={pid}, Command='{full_command}', User={user}, Description='{analysis['process_explanation']}'")

    # Keep the process alive to prevent immediate exit
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
