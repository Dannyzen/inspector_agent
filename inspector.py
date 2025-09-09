
import asyncio
import subprocess
import logging

logging.basicConfig(level=logging.INFO)

async def main():
    seen_processes = set()
    logging.info("Starting inspector")
    while True:
        logging.info("Running lsof")
        process = await asyncio.create_subprocess_shell(
            "lsof -Pni",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        output = stdout.decode()
        for line in output.strip().split("\n"):
            if "LISTEN" in line and line not in seen_processes:
                logging.info(f"Found new listening process: {line}")
                with open("inspector.log", "a") as f:
                    f.write(line + "\n")
                seen_processes.add(line)
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
