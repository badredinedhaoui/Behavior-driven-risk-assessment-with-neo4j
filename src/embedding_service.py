"""
Local Embedding Service using sentence-transformers
No external API calls - runs 100% locally
"""
import numpy as np
from sentence_transformers import SentenceTransformer
from typing import List, Union
import logging
from config import EMBEDDING_MODEL, EMBEDDING_DIMENSION

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LocalEmbeddingService:
    """
    Generates embeddings locally using sentence-transformers.
    Uses all-MiniLM-L6-v2 (384 dimensions, fast, good quality)
    """
    
    def __init__(self, model_name: str = EMBEDDING_MODEL):
        logger.info(f"Loading embedding model: {model_name}")
        self.model = SentenceTransformer(model_name)
        self.dimension = EMBEDDING_DIMENSION
        logger.info(f"Model loaded. Embedding dimension: {self.dimension}")
    
    def embed_text(self, text: str) -> List[float]:
        """Embed a single text string."""
        embedding = self.model.encode(text, convert_to_numpy=True)
        return embedding.tolist()
    
    def embed_batch(self, texts: List[str], batch_size: int = 32) -> List[List[float]]:
        """Embed multiple texts efficiently."""
        embeddings = self.model.encode(
            texts,
            batch_size=batch_size,
            show_progress_bar=True,
            convert_to_numpy=True
        )
        return embeddings.tolist()
    
    def compute_similarity(self, embedding1: List[float], embedding2: List[float]) -> float:
        """Compute cosine similarity between two embeddings."""
        vec1 = np.array(embedding1)
        vec2 = np.array(embedding2)
        return float(np.dot(vec1, vec2) / (np.linalg.norm(vec1) * np.linalg.norm(vec2)))


# Singleton instance
_embedding_service = None

def get_embedding_service() -> LocalEmbeddingService:
    """Get or create the embedding service singleton."""
    global _embedding_service
    if _embedding_service is None:
        _embedding_service = LocalEmbeddingService()
    return _embedding_service


if __name__ == "__main__":
    # Test the embedding service
    service = get_embedding_service()
    
    test_texts = [
        "Phishing email with malicious attachment",
        "User clicked on suspicious link",
        "PowerShell executing encoded command",
        "Credential dumping using mimikatz"
    ]
    
    print("Testing embedding service...")
    embeddings = service.embed_batch(test_texts)
    
    for i, text in enumerate(test_texts):
        print(f"Text: {text[:50]}...")
        print(f"Embedding shape: {len(embeddings[i])} dimensions")
        print(f"First 5 values: {embeddings[i][:5]}")
        print()
    
    # Test similarity
    sim = service.compute_similarity(embeddings[0], embeddings[1])
    print(f"Similarity between text 0 and 1: {sim:.4f}")