# How to Run the Inspector Agent

This document explains how to run the Inspector Agent project.

## Prerequisites

- Python 3

## Setup

1.  **Create a virtual environment:**

    ```bash
    python3 -m venv .venv
    ```

2.  **Install the dependencies:**

    ```bash
    ./.venv/bin/python3 -m pip install -r requirements.txt
    ```

## Running the Agent

1.  **Start the agent:**

    ```bash
    ./.venv/bin/python3 main.py
    ```

2.  **Test the agent:**

    In a separate terminal, open a port to test the agent:

    ```bash
    nc -l 8080
    ```

    You should see output in the agent's terminal indicating that it has detected the `nc` process.

## Simulating a Threat

To test the `ThreatAnalyzer` agent, you can simulate a threat by running a process that is flagged as malicious.

1.  **Run the simulated threat command:**

    In a separate terminal, run the following command:

    ```bash
    nc -l 8083
    ```

2.  **Observe the output:**

    The `ThreatAnalyzer` agent will identify the `nc` process listening on port 8083 as a potential threat, display it in the output table, and the `Remediation` tool will terminate the process.