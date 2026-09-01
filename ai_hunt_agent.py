import ollama
import json


class ThreatHuntAgent:
    """
    Local AI-assisted threat hunting agent.

    The AI analyzes information provided by the human analyst.
    It does NOT directly access the SIEM or execute commands.
    """

    SYSTEM_PROMPT = """
You are a cybersecurity threat-hunting assistant helping a human analyst.

Your job is to analyze security logs and identify suspicious behavior.

IMPORTANT RULES:

1. Only use evidence provided by the analyst.
2. NEVER invent log events, users, IP addresses, timestamps, or processes.
3. Clearly separate FACTS from HYPOTHESES.
4. Never claim an incident is confirmed without sufficient evidence.
5. Give a confidence level: HIGH, MEDIUM, or LOW.
6. Recommend validation steps for the human analyst.
7. Be conservative when assigning MITRE ATT&CK techniques.
8. NEVER invent MITRE ATT&CK technique IDs.
9. If you are uncertain about an ATT&CK mapping, say "Needs ATT&CK validation".
10. The human analyst makes the final decision.

RELEVANT ATT&CK TECHNIQUES FOR THIS HUNT:

T1078 - Valid Accounts
Use when legitimate account credentials may be abused.

T1021 - Remote Services
Use when authentication suggests access to another system through
remote services.

T1021.001 - Remote Services: RDP
Use only when evidence specifically indicates RDP.

T1021.002 - Remote Services: SMB/Windows Admin Shares
Use only when evidence specifically indicates SMB or Windows
administrative shares.

T1021.004 - Remote Services: SSH
Use only when evidence specifically indicates SSH.

Do NOT use these techniques unless their required evidence exists.

For every investigation, use this format:

FINDING:

FACTS:
- Facts directly supported by the logs.

ANOMALY:
- What differs from the apparent baseline.

BENIGN EXPLANATIONS:
- Possible legitimate explanations.

MALICIOUS HYPOTHESES:
- Possible attacker explanations.

MITRE ATT&CK:
- Technique ID and name.
- Explain exactly why the evidence supports it.
- If insufficient evidence exists, say "Needs ATT&CK validation."

CONFIDENCE:
HIGH / MEDIUM / LOW

RECOMMENDED VALIDATION:
- Specific additional evidence the analyst should collect.

FINAL ASSESSMENT:
- State whether this is suspicious, inconclusive, or likely benign.
- Never state that compromise is confirmed unless the evidence
  actually proves it.

Keep the analysis concise and evidence-based.
"""

    def __init__(self, model="qwen3:8b"):
        self.model = model
        self.conversation_history = []

    def analyze(self, prompt, data_context=None):

        full_prompt = prompt

        if data_context:
            full_prompt += f"""

DATA PROVIDED BY ANALYST:
{data_context}
"""

        messages = [
            {
                "role": "system",
                "content": self.SYSTEM_PROMPT
            },
            *self.conversation_history,
            {
                "role": "user",
                "content": full_prompt
            }
        ]

        response = ollama.chat(
            model=self.model,
            messages=messages
        )

        answer = response["message"]["content"]

        self.conversation_history.append(
            {
                "role": "user",
                "content": full_prompt
            }
        )

        self.conversation_history.append(
            {
                "role": "assistant",
                "content": answer
            }
        )

        return answer

    def reset(self):
        """Clear the conversation history."""
        self.conversation_history = []


if __name__ == "__main__":

    agent = ThreatHuntAgent()

    result = agent.analyze(
        """
Analyze this hypothetical authentication event:

User: alice
Source IP: 10.10.20.15
Destination computers: DC01, FILE01, WEB01, SQL01, APP01
Time: 02:13 AM
Number of logins: 5
Time span: 90 seconds

Could this indicate credential abuse or lateral movement?
Explain what evidence we have and what additional evidence
we should collect before deciding.
"""
    )

    print("\n" + "=" * 70)
    print("AI THREAT HUNT ANALYSIS")
    print("=" * 70)
    print(result)