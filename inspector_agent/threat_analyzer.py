from google.adk.agents import LlmAgent
from .remediation_tool import remediation_tool

threat_analyzer = LlmAgent(
    name="threat_analyzer",
    description="Analyzes a process and returns a risk score.",
    instruction="""
    You are a security expert. Given the following process information,
    assess the risk on a scale of 1-10, where 1 is no risk and 10 is a
    critical threat. Provide a brief justification for your assessment.

    Process: {process_info}

    If the risk score is 7 or higher, use the remediation_tool to kill the process.

    Return your response in the following format:
    Risk Score: [score]
    Justification: [justification]
    """,
    tools=[remediation_tool],
    output_key="threat_analysis",
)
