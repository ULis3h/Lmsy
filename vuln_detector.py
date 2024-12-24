import requests
from bs4 import BeautifulSoup
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
import faiss
from sqlalchemy import create_engine, Column, Integer, String, Float, JSON
from sqlalchemy.orm import declarative_base, sessionmaker
import json

Base = declarative_base()

class VulnerableVector(Base):
    __tablename__ = 'vulnerable_vectors'
    
    id = Column(Integer, primary_key=True)
    url = Column(String)
    vector = Column(String)  # JSON string of vector
    vulnerability_type = Column(String)
    vulnerability_details = Column(JSON)

class VulnDetector:
    def __init__(self, db_path="sqlite:///vuln_vectors.db"):
        self.vectorizer = TfidfVectorizer(max_features=100)
        self.engine = create_engine(db_path)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        
        # Initialize FAISS index
        self.dimension = 100  # Same as max_features in TfidfVectorizer
        self.index = faiss.IndexFlatL2(self.dimension)
        self._load_vectors()

    def _load_vectors(self):
        """Load existing vectors from database into FAISS index"""
        session = self.Session()
        vectors = session.query(VulnerableVector).all()
        if vectors:
            all_vectors = [np.array(json.loads(v.vector)) for v in vectors]
            self.index.add(np.array(all_vectors).astype('float32'))
        session.close()

    def _fetch_site_content(self, url):
        """Fetch and parse website content"""
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            # Extract relevant features (can be expanded)
            text_content = soup.get_text()
            headers = str(response.headers)
            return f"{text_content} {headers}"
        except Exception as e:
            raise Exception(f"Error fetching site content: {str(e)}")

    def _generate_vector(self, content):
        """Generate vector from site content"""
        try:
            vector_matrix = self.vectorizer.fit_transform([content])
            return vector_matrix.toarray()[0]
        except Exception as e:
            raise Exception(f"Error generating vector: {str(e)}")

    def analyze_url(self, url):
        """Analyze a URL for potential vulnerabilities"""
        # Fetch and analyze site
        content = self._fetch_site_content(url)
        vector = self._generate_vector(content)
        
        # Search similar vectors
        k = 5  # Number of similar vectors to retrieve
        D, I = self.index.search(np.array([vector]).astype('float32'), k)
        
        # Get vulnerability information for similar vectors
        session = self.Session()
        similar_vectors = session.query(VulnerableVector).all()
        potential_vulnerabilities = []
        
        for i, distance in zip(I[0], D[0]):
            if i < len(similar_vectors):
                vuln = similar_vectors[i]
                potential_vulnerabilities.append({
                    'similarity_score': float(1 / (1 + distance)),
                    'vulnerability_type': vuln.vulnerability_type,
                    'details': vuln.vulnerability_details,
                    'similar_url': vuln.url
                })
        
        session.close()
        return {
            'url': url,
            'potential_vulnerabilities': potential_vulnerabilities
        }

    def add_vulnerable_site(self, url, vulnerability_type, vulnerability_details):
        """Add a known vulnerable site to the database"""
        try:
            content = self._fetch_site_content(url)
            vector = self._generate_vector(content)
            
            session = self.Session()
            vuln_vector = VulnerableVector(
                url=url,
                vector=json.dumps(vector.tolist()),
                vulnerability_type=vulnerability_type,
                vulnerability_details=vulnerability_details
            )
            session.add(vuln_vector)
            session.commit()
            session.close()
            
            # Update FAISS index
            self.index.add(np.array([vector]).astype('float32'))
            return True
        except Exception as e:
            raise Exception(f"Error adding vulnerable site: {str(e)}")
