# These remain stubs. Replace with real ML models or API calls.
def nsfw_score_image(path) -> float:
    """
    Return a float in [0,1] representing NSFW probability.
    """
    # TODO: load model and run inference
    # For now apply simple heuristic: image files -> 0.45
    return 0.45

def gore_score_image(path) -> float:
    return 0.05

def deepfake_score_image(path) -> float:
    # Optionally call external service (aiornot) with consent
    return 0.02
