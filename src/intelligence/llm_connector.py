"""
Compatibility wrapper for LLMConnector expected by main.py.
Ollama does not require api_key; we accept it and ignore it.
"""
from .ollama_connector import OllamaWSLConnector

class LLMConnector(OllamaWSLConnector):
    def __init__(self, *args, api_key=None, **kwargs):
        super().__init__(*args, **kwargs)
