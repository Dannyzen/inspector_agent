
import asyncio
import subprocess
import logging
from threat_analyzer import ThreatAnalyzer

logging.basicConfig(level=logging.INFO)

async def main():
    seen_processes = set()
    analyzer = ThreatAnalyzer()
    logging.info("Starting inspector")
    try:
        while True:
            lsof_process = await asyncio.create_subprocess_shell(
                "lsof -Pni",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            lsof_stdout, _ = await lsof_process.communicate()
            output = lsof_stdout.decode()
            for line in output.strip().split("\n"):
                if "LISTEN" in line and line not in seen_processes:
                    parts = line.split()
                    pid = parts[1]
                    user = parts[2]
                    address_column = parts[8]
                    port = address_column.split(":")[-1]

                    # Get the full command line for the process
                    ps_process = await asyncio.create_subprocess_shell(
                        f"ps -o cmd= -p {pid}",
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    ps_stdout, _ = await ps_process.communicate()
                    full_command = ps_stdout.decode().strip()

                    analysis = analyzer.analyze(full_command, port)

                    if analysis["is_threat"]:
                        logging.warning(f"Potential Threat Detected:")
                        logging.warning(f"  PID: {pid}, Command: '{full_command}', User: {user}")
                        logging.warning(f"  Process Explanation: {analysis['process_explanation']}")
                        logging.warning(f"  Rationale: {analysis['rationale']}")
                        log_entry = f"{{'pid': '{pid}', 'command': '{full_command}', 'user': '{user}', 'status': 'threat', 'port': '{port}'}}\n"
                        with open("inspector.log", "a") as f:
                            f.write(log_entry)
                    else:
                        logging.info(f"Found new listening process: PID={pid}, Command='{full_command}', User={user}")
                        log_entry = f"{{'pid': '{pid}', 'command': '{full_command}', 'user': '{user}'}}\n"
                        with open("inspector.log", "a") as f:
                            f.write(log_entry)
                    seen_processes.add(line)
            await asyncio.sleep(1)
    finally:
        logging.info("Stopping inspector")

if __name__ == "__main__":
    asyncio.run(main())
