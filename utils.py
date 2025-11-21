import random
import yaml
import pickle


def insecure_eval(expr: str):
    # Dangerous pattern: eval on user-controlled input
    return eval(expr)  # nosec


def generate_insecure_token():
    # Uses non-cryptographic randomness for security-sensitive token
    return str(random.random())


def load_yaml(data: str):
    # Unsafe YAML load (can lead to code execution with certain payloads)
    return yaml.load(data)  # PyYAML unsafe loader


def insecure_deserialize(data: bytes):
    # Insecure deserialization of untrusted data
    return pickle.loads(data)
