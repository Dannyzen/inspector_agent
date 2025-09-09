import os
import signal
from google.adk.tools import FunctionTool, ToolContext

def remediate_process(pid: int, tool_context: ToolContext) -> str:
    """
    Kills a process by its PID.

    Args:
        pid: The process ID to kill.
        tool_context: The tool context.

    Returns:
        A string indicating the result of the operation.
    """
    try:
        os.kill(pid, signal.SIGKILL)
        return f"Process {pid} killed."
    except ProcessLookupError:
        return f"Process {pid} not found."
    except Exception as e:
        return f"Error killing process {pid}: {e}"

remediation_tool = FunctionTool(
    func=remediate_process,
)
