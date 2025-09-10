import asyncio
import logging
import subprocess
from threat_analyzer import ThreatAnalyzer

logging.basicConfig(level=logging.INFO, format='%(message)s')

async def main():
    """
    This is the main entry point for the application.
    It runs the inspector agent.
    """
    seen_processes = set()
    analyzer = ThreatAnalyzer()
    
    # Table header
    header = f"{'PID':<10} {'USER':<10} {'COMMAND':<40} {'DESCRIPTION':<70} {'STATUS':<10}"
    logging.info("Starting inspector")
    logging.info(header)
    logging.info("-" * len(header))

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
                    
                    import re
                    match = re.search(r':(\d+)$', address_column)
                    if not match:
                        continue
                    port = match.group(1)

                    ps_process = await asyncio.create_subprocess_shell(
                        f"ps -o cmd= -p {pid}",
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    ps_stdout, _ = await ps_process.communicate()
                    full_command = ps_stdout.decode().strip()

                    analysis = analyzer.analyze(full_command, port)

                    if analysis["is_threat"]:
                        status = "THREAT"
                        description = analysis['rationale']
                        row = f"{pid:<10} {user:<10} {full_command:<40} {description:<70} {status:<10}"
                        logging.warning(row)
                        if analyzer.remediation.kill_process(pid):
                            logging.warning(f"  Action: Process {pid} terminated.")
                        else:
                            logging.warning(f"  Action: Failed to terminate process {pid}.")
                        log_entry = f"{{'pid': '{pid}', 'command': '{full_command}', 'user': '{user}', 'status': 'threat', 'port': '{port}'}}\n"
                        with open("inspector.log", "a") as f:
                            f.write(log_entry)
                    else:
                        status = "Normal"
                        description = analysis['process_explanation']
                        row = f"{pid:<10} {user:<10} {full_command:<40} {description:<70} {status:<10}"
                        logging.info(row)
                        log_entry = f"{{'pid': '{pid}', 'command': '{full_command}', 'user': '{user}', 'description': '{analysis['process_explanation']}'}}\n"
                        with open("inspector.log", "a") as f:
                            f.write(log_entry)
                    seen_processes.add(line)
            await asyncio.sleep(1)
    finally:
        logging.info("Stopping inspector")

if __name__ == "__main__":
    asyncio.run(main())
