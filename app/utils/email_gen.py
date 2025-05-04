from builtins import str
import random


def generate_email() -> str:
    """Generate a URL-safe email using adjectives and planets."""
    adjectives = ["clever", "jolly", "brave", "sly", "gentle"]
    planets = ["pluto", "mars", "venus", "saturn", "neptune"]
    number = random.randint(0, 999)
    return f"{random.choice(adjectives)}_{random.choice(planets)}_{number}@example.com"