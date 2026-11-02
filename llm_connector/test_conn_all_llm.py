"""
This is a testing hub for conn_all_llm.py

"""

import os
import sys
from pathlib import Path

# 1. Add the agent folder to sys.path
root_path = Path(__file__).resolve().parent.parent
agent_dir = root_path / "vulnhunter-agent" / "agent"
sys.path.append(str(agent_dir))

# 2. Set a temporary environment variable for testing
os.environ["VULNHUNT_ANTHROPIC_MODEL"] = "deepseek-chat"
os.environ["VULNHUNT_ANTHROPIC_AUTH_MODE"] = "deepseek"

# 3. Import config and load it
import config

cfg = config.load_config()
print("Success! Model:", cfg.anthropic.model)
print("Auth Mode:", cfg.anthropic.auth_mode)
print("Base URL:", cfg.anthropic.base_url)