"""
 The changing_llms workflow allows your VulnHunter PyQt6 graphical user interface
 to dynamically switch its underlying intelligence engine. Instead of being locked into Claude,
 the application reads your configuration to route requests seamlessly to Claude, DeepSeek (via its Anthropic-compatible gateway),
 or Gemini using a unified interface wrapper.

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

def start_scan():
    """Placeholder function for starting the vulnerability scan workflow."""
    pass


class LLMConnector:
    """
    A unified router class that abstracts away the underlying AI model provider,
    making it simple for the PyQt6 GUI to send prompts and receive responses
    regardless of whether Claude, DeepSeek, or Gemini is selected.
    """
    
    def __init__(self, model_name: str):
        """
        Initializes the connector based on the user's selection from the GUI dropdown.
        
        :param model_name: A string representing the active model ('claude', 'deepseek', or 'gemini')
        """
        self.model_name = model_name.lower().strip()
        
        # Dictionary or conditional setup to configure credentials based on the selected model
        self._configure_model_credentials()

    def _configure_model_credentials(self):
        """
        Internal helper method to load API keys, base URLs, and model IDs 
        from your config module depending on the active model choice.
        """
        if self.model_name == "deepseek":
            # DeepSeek runs through an Anthropic-compatible gateway in your setup
            self.auth_mode = getattr(config.anthropic, "auth_mode", "deepseek")
            self.base_url = getattr(config.anthropic, "base_url", "https://api.deepseek.com/anthropic")
            self.api_key = getattr(config.anthropic, "api_key", None)
            self.model_id = getattr(config.anthropic, "model", "deepseek-chat")
            
            # Print statements for debugging/verification as seen in your workspace snippet
            print(f"[LLMConnector] Loaded DeepSeek Config -> Auth Mode: {self.auth_mode}")
            print(f"[LLMConnector] Base URL: {self.base_url}")
            
        elif self.model_name == "claude":
            # Standard Claude / Anthropic configuration setup
            self.api_key = getattr(config.anthropic, "api_key", None)
            self.model_id = getattr(config.anthropic, "model", "claude-3-5-sonnet")
            print(f"[LLMConnector] Loaded Claude Config -> Model ID: {self.model_id}")
            
        elif self.model_name == "gemini":
            # Gemini configuration setup (adjust attribute names to match your config structure)
            # Example placeholder: self.api_key = getattr(config, "gemini_api_key", None)
            print("[LLMConnector] Loaded Gemini Config")
            
        else:
            raise ValueError(f"Unsupported model name provided: '{self.model_name}'. Choose 'claude', 'deepseek', or 'gemini'.")

    def generate_response(self, prompt):
        """
        The single entry point for your PyQt6 GUI to generate AI completions.
        It routes the prompt to the correct model client under the hood.
        
        :param prompt: The text query or vulnerability scan payload to send.
        :return: The string response from the active language model.
        """
        if self.model_name == "deepseek":
            # TODO: Call your DeepSeek/Anthropic-compatible client execution logic here
            return f"[DeepSeek Response Simulated]: Processed query -> '{prompt}'"
            
        elif self.model_name == "claude":
            # TODO: Call your Claude client execution logic here
            return f"[Claude Response Simulated]: Processed query -> '{prompt}'"
            
        elif self.model_name == "gemini":
            # TODO: Call your Gemini client execution logic here
            return f"[Gemini Response Simulated]: Processed query -> '{prompt}'"
            
        else:
            return "Error: No active model configured."