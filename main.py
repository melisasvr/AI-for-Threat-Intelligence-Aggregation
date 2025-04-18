import re
import json
import datetime
import requests
import pandas as pd
import numpy as np
from typing import List, Dict, Any, Set, Tuple
from dataclasses import dataclass, field
from collections import Counter, defaultdict

# For NLP processing
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk.stem import WordNetLemmatizer
import spacy

# For visualization
import matplotlib.pyplot as plt
import seaborn as sns

# Download required NLTK resources
nltk.download('punkt', quiet=True)
nltk.download('stopwords', quiet=True)
nltk.download('wordnet', quiet=True)

# Load spaCy model
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    print("Downloading spaCy model...")
    import subprocess
    subprocess.run(["python", "-m", "spacy", "download", "en_core_web_sm"])
    nlp = spacy.load("en_core_web_sm")

@dataclass
class IOC:
    """Class for representing Indicators of Compromise"""
    value: str
    ioc_type: str
    source: str
    timestamp: datetime.datetime
    context: str = ""
    confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert IOC to dictionary format"""
        return {
            "value": self.value,
            "ioc_type": self.ioc_type,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "context": self.context,
            "confidence": self.confidence
        }

@dataclass
class ThreatIntelligence:
    """Class for aggregating and analyzing threat intelligence"""
    iocs: List[IOC] = field(default_factory=list)
    feeds: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    trends: Dict[str, Any] = field(default_factory=dict)
    
    def add_ioc(self, ioc: IOC) -> None:
        """Add an IOC to the collection"""
        self.iocs.append(ioc)
    
    def add_feed(self, name: str, url: str, ioc_types: List[str]) -> None:
        """Register a new threat feed"""
        self.feeds[name] = {
            "url": url,
            "ioc_types": ioc_types,
            "last_updated": None
        }
    
    def save_to_file(self, filename: str) -> None:
        """Save the current state to a JSON file"""
        data = {
            "iocs": [ioc.to_dict() for ioc in self.iocs],
            "feeds": self.feeds,
            "trends": self.trends,
            "timestamp": datetime.datetime.now().isoformat()
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"Data saved to {filename}")
    
    def load_from_file(self, filename: str) -> None:
        """Load state from a JSON file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            # Load IOCs
            self.iocs = []
            for ioc_data in data.get("iocs", []):
                self.iocs.append(IOC(
                    value=ioc_data["value"],
                    ioc_type=ioc_data["ioc_type"],
                    source=ioc_data["source"],
                    timestamp=datetime.datetime.fromisoformat(ioc_data["timestamp"]),
                    context=ioc_data.get("context", ""),
                    confidence=ioc_data.get("confidence", 0.0)
                ))
            
            # Load feeds
            self.feeds = data.get("feeds", {})
            
            # Load trends
            self.trends = data.get("trends", {})
            
            print(f"Loaded {len(self.iocs)} IOCs from {filename}")
        except FileNotFoundError:
            print(f"File {filename} not found. Starting with empty state.")
        except json.JSONDecodeError:
            print(f"Error parsing {filename}. Starting with empty state.")


class IOCExtractor:
    """Class for extracting IOCs from text using regular expressions and NLP"""
    
    # Regex patterns for common IOC types
    PATTERNS = {
        "ipv4": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        "ipv6": r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
        "domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
        "url": r"\bhttps?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "md5": r"\b[a-fA-F0-9]{32}\b",
        "sha1": r"\b[a-fA-F0-9]{40}\b",
        "sha256": r"\b[a-fA-F0-9]{64}\b",
        "bitcoin_address": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        "cve": r"\bCVE-\d{4}-\d{4,7}\b"
    }
    
    # Common false positives to filter out
    FALSE_POSITIVES = {
        "ipv4": ["0.0.0.0", "127.0.0.1", "255.255.255.255"],
        "domain": ["example.com", "domain.com", "test.com"],
        "url": ["http://example.com", "https://example.com"],
        "email": ["user@example.com", "info@example.com"]
    }
    
    def __init__(self):
        """Initialize the IOC extractor"""
        self.compiled_patterns = {
            ioc_type: re.compile(pattern, re.IGNORECASE) 
            for ioc_type, pattern in self.PATTERNS.items()
        }
    
    def extract_from_text(self, text: str, source: str) -> List[IOC]:
        """Extract all IOCs from a text"""
        iocs = []
        timestamp = datetime.datetime.now()
        
        # Get surrounding context for IOCs (simplified)
        def get_context(match, text, window=50):
            start = max(0, match.start() - window)
            end = min(len(text), match.end() + window)
            return text[start:end].replace("\n", " ").strip()
        
        # Extract using regex patterns
        for ioc_type, pattern in self.compiled_patterns.items():
            for match in pattern.finditer(text):
                value = match.group(0)
                
                # Skip false positives
                if ioc_type in self.FALSE_POSITIVES and value.lower() in [fp.lower() for fp in self.FALSE_POSITIVES[ioc_type]]:
                    continue
                
                context = get_context(match, text)
                
                # Calculate a simple confidence score based on context
                confidence = self._calculate_confidence(value, ioc_type, context)
                
                iocs.append(IOC(
                    value=value,
                    ioc_type=ioc_type,
                    source=source,
                    timestamp=timestamp,
                    context=context,
                    confidence=confidence
                ))
        
        return iocs
    
    def _calculate_confidence(self, value: str, ioc_type: str, context: str) -> float:
        """Calculate a confidence score for the IOC based on context"""
        # This is a simplified implementation - could be improved with ML
        confidence = 0.7  # Base confidence
        
        # Adjust based on context words
        threat_keywords = ["malware", "ransomware", "threat", "attack", "compromise", 
                         "phishing", "malicious", "suspicious", "vulnerability"]
        
        # Check for threat keywords in context
        context_lower = context.lower()
        keyword_matches = sum(1 for keyword in threat_keywords if keyword in context_lower)
        confidence += min(0.2, keyword_matches * 0.05)  # Max boost of 0.2
        
        # Penalize if context contains words suggesting benign use
        benign_keywords = ["example", "test", "documentation", "placeholder", "sample"]
        benign_matches = sum(1 for keyword in benign_keywords if keyword in context_lower)
        confidence -= min(0.3, benign_matches * 0.1)  # Max penalty of 0.3
        
        # Adjust for specific IOC types
        if ioc_type == "ipv4":
            # Penalize private IP addresses
            if (value.startswith("10.") or value.startswith("192.168.") or 
                    value.startswith("172.") and 16 <= int(value.split(".")[1]) <= 31):
                confidence -= 0.3
        
        # Ensure confidence is between 0 and 1
        return max(0.0, min(1.0, confidence))


class TrendAnalyzer:
    """Class for analyzing trends in threat intelligence data"""
    
    def __init__(self, ti: ThreatIntelligence):
        """Initialize with a ThreatIntelligence instance"""
        self.ti = ti
        self.lemmatizer = WordNetLemmatizer()
        self.stop_words = set(stopwords.words('english'))
    
    def analyze(self) -> Dict[str, Any]:
        """Perform analysis on the IOCs and their context"""
        results = {}
        
        # Basic statistics
        results["total_iocs"] = len(self.ti.iocs)
        results["ioc_types"] = self._count_ioc_types()
        results["sources"] = self._count_sources()
        results["time_series"] = self._analyze_time_series()
        
        # NLP analysis of context
        results["topics"] = self._extract_topics()
        results["entities"] = self._extract_entities()
        
        # Find related IOCs
        results["related_iocs"] = self._find_related_iocs()
        
        # Store results in the ThreatIntelligence object
        self.ti.trends = results
        
        return results
    
    def _count_ioc_types(self) -> Dict[str, int]:
        """Count occurrences of each IOC type"""
        return Counter(ioc.ioc_type for ioc in self.ti.iocs)
    
    def _count_sources(self) -> Dict[str, int]:
        """Count occurrences of each source"""
        return Counter(ioc.source for ioc in self.ti.iocs)
    
    def _analyze_time_series(self) -> Dict[str, Any]:
        """Analyze IOCs over time"""
        # Group IOCs by day
        dates = [ioc.timestamp.date() for ioc in self.ti.iocs]
        date_counts = Counter(dates)
        
        # Sort by date
        sorted_dates = sorted(date_counts.items())
        
        return {
            "dates": [date.isoformat() for date, _ in sorted_dates],
            "counts": [count for _, count in sorted_dates]
        }
    
    def _extract_topics(self) -> Dict[str, int]:
        """Extract common topics from IOC context using NLP"""
        all_text = " ".join(ioc.context for ioc in self.ti.iocs)
        
        # Tokenize and clean text
        tokens = word_tokenize(all_text.lower())
        tokens = [self.lemmatizer.lemmatize(token) for token in tokens 
                 if token.isalpha() and token not in self.stop_words]
        
        # Extract common terms
        topic_counts = Counter(tokens).most_common(20)
        return {term: count for term, count in topic_counts}
    
    def _extract_entities(self) -> Dict[str, List[str]]:
        """Extract named entities from IOC context using spaCy"""
        all_text = " ".join(ioc.context for ioc in self.ti.iocs)
        
        # Process with spaCy
        doc = nlp(all_text)
        
        # Extract entities by type
        entities = defaultdict(list)
        for ent in doc.ents:
            entities[ent.label_].append(ent.text)
        
        # Count occurrences
        entity_counts = {
            ent_type: Counter(ents).most_common(5)
            for ent_type, ents in entities.items()
        }
        
        return entity_counts
    
    def _find_related_iocs(self) -> List[List[str]]:
        """Find potentially related IOCs based on shared context"""
        # This is a simplified implementation that could be enhanced with ML
        related_groups = []
        
        # Group by shared words in context
        context_words = {}
        for i, ioc in enumerate(self.ti.iocs):
            # Extract significant words from context
            words = set(word_tokenize(ioc.context.lower()))
            words = {self.lemmatizer.lemmatize(word) for word in words 
                    if word.isalpha() and word not in self.stop_words}
            
            for word in words:
                if word not in context_words:
                    context_words[word] = []
                context_words[word].append(i)
        
        # Find groups with significant overlap
        processed = set()
        for indices in context_words.values():
            if len(indices) >= 2:  # At least 2 IOCs share this word
                # Convert to set of IOC values for deduplication
                ioc_values = {self.ti.iocs[i].value for i in indices}
                
                # Skip if we've processed these exact IOCs already
                ioc_key = frozenset(ioc_values)
                if ioc_key in processed or len(ioc_values) < 2:
                    continue
                
                related_groups.append(list(ioc_values))
                processed.add(ioc_key)
        
        return related_groups


class FeedProcessor:
    """Class for processing different types of threat feeds"""
    
    def __init__(self, ti: ThreatIntelligence, extractor: IOCExtractor):
        """Initialize with ThreatIntelligence and IOCExtractor instances"""
        self.ti = ti
        self.extractor = extractor
    
    def process_all_feeds(self) -> None:
        """Process all registered feeds"""
        for feed_name, feed_info in self.ti.feeds.items():
            try:
                print(f"Processing feed: {feed_name}")
                self.process_feed(feed_name)
            except Exception as e:
                print(f"Error processing feed {feed_name}: {str(e)}")
    
    def process_feed(self, feed_name: str) -> None:
        """Process a specific feed"""
        if feed_name not in self.ti.feeds:
            raise ValueError(f"Feed '{feed_name}' not registered")
        
        feed_info = self.ti.feeds[feed_name]
        url = feed_info["url"]
        
        # Fetch the feed
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        # Process based on content type
        content_type = response.headers.get('Content-Type', '')
        
        if 'json' in content_type:
            self._process_json_feed(feed_name, response.json())
        elif 'xml' in content_type:
            # For XML, we'd need to add an XML parser
            print(f"XML feeds not yet supported: {feed_name}")
        elif 'csv' in content_type or url.endswith('.csv'):
            self._process_csv_feed(feed_name, response.text)
        elif 'text' in content_type or 'plain' in content_type:
            self._process_text_feed(feed_name, response.text)
        else:
            # Default to treating it as text
            self._process_text_feed(feed_name, response.text)
        
        # Update last_updated timestamp
        self.ti.feeds[feed_name]["last_updated"] = datetime.datetime.now().isoformat()
    
    def _process_json_feed(self, feed_name: str, data: Dict[str, Any]) -> None:
        """Process a JSON format feed"""
        # This is a simplified implementation - in reality, we'd need to handle
        # different JSON structures based on the specific feed
        
        # Convert JSON to text for IOC extraction
        text = json.dumps(data)
        iocs = self.extractor.extract_from_text(text, feed_name)
        
        # Add extracted IOCs
        for ioc in iocs:
            self.ti.add_ioc(ioc)
        
        print(f"Extracted {len(iocs)} IOCs from JSON feed: {feed_name}")
    
    def _process_csv_feed(self, feed_name: str, text: str) -> None:
        """Process a CSV format feed"""
        try:
            # Parse CSV
            df = pd.read_csv(pd.StringIO(text))
            
            # Extract IOCs from each row
            total_iocs = 0
            for _, row in df.iterrows():
                # Convert row to string
                row_text = " ".join(str(val) for val in row.values if pd.notna(val))
                iocs = self.extractor.extract_from_text(row_text, feed_name)
                
                # Add extracted IOCs
                for ioc in iocs:
                    self.ti.add_ioc(ioc)
                
                total_iocs += len(iocs)
            
            print(f"Extracted {total_iocs} IOCs from CSV feed: {feed_name}")
        except Exception as e:
            print(f"Error processing CSV feed {feed_name}: {str(e)}")
    
    def _process_text_feed(self, feed_name: str, text: str) -> None:
        """Process a plain text feed"""
        iocs = self.extractor.extract_from_text(text, feed_name)
        
        # Add extracted IOCs
        for ioc in iocs:
            self.ti.add_ioc(ioc)
        
        print(f"Extracted {len(iocs)} IOCs from text feed: {feed_name}")


class Visualizer:
    """Class for visualizing threat intelligence data"""
    
    def __init__(self, ti: ThreatIntelligence):
        """Initialize with a ThreatIntelligence instance"""
        self.ti = ti
    
    def plot_ioc_types(self, save_path: str = None) -> None:
        """Plot distribution of IOC types"""
        if not self.ti.iocs:
            print("No IOCs to visualize")
            return
        
        # Count IOC types
        ioc_types = Counter(ioc.ioc_type for ioc in self.ti.iocs)
        
        # Create figure
        plt.figure(figsize=(10, 6))
        
        # Create bar chart
        sns.barplot(x=list(ioc_types.keys()), y=list(ioc_types.values()))
        plt.title('Distribution of IOC Types')
        plt.xlabel('IOC Type')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        
        # Adjust layout
        plt.tight_layout()
        
        # Save or show
        if save_path:
            plt.savefig(save_path)
            print(f"Plot saved to {save_path}")
        else:
            plt.show()
    
    def plot_time_series(self, save_path: str = None) -> None:
        """Plot IOCs over time"""
        if not self.ti.iocs:
            print("No IOCs to visualize")
            return
        
        # Group IOCs by day
        dates = [ioc.timestamp.date() for ioc in self.ti.iocs]
        date_counts = Counter(dates)
        
        # Sort by date
        sorted_dates = sorted(date_counts.items())
        x = [date for date, _ in sorted_dates]
        y = [count for _, count in sorted_dates]
        
        # Create figure
        plt.figure(figsize=(12, 6))
        
        # Create line chart
        plt.plot(x, y, marker='o')
        plt.title('IOCs Over Time')
        plt.xlabel('Date')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        
        # Adjust layout
        plt.tight_layout()
        
        # Save or show
        if save_path:
            plt.savefig(save_path)
            print(f"Plot saved to {save_path}")
        else:
            plt.show()
    
    def plot_confidence_distribution(self, save_path: str = None) -> None:
        """Plot distribution of confidence scores"""
        if not self.ti.iocs:
            print("No IOCs to visualize")
            return
        
        # Get confidence scores
        confidence_scores = [ioc.confidence for ioc in self.ti.iocs]
        
        # Create figure
        plt.figure(figsize=(10, 6))
        
        # Create histogram
        sns.histplot(confidence_scores, bins=10, kde=True)
        plt.title('Distribution of IOC Confidence Scores')
        plt.xlabel('Confidence Score')
        plt.ylabel('Count')
        
        # Adjust layout
        plt.tight_layout()
        
        # Save or show
        if save_path:
            plt.savefig(save_path)
            print(f"Plot saved to {save_path}")
        else:
            plt.show()
    
    def plot_sources(self, save_path: str = None) -> None:
        """Plot distribution of sources"""
        if not self.ti.iocs:
            print("No IOCs to visualize")
            return
        
        # Count sources
        sources = Counter(ioc.source for ioc in self.ti.iocs)
        
        # Create figure
        plt.figure(figsize=(10, 6))
        
        # Create pie chart
        plt.pie(sources.values(), labels=sources.keys(), autopct='%1.1f%%')
        plt.title('Distribution of IOC Sources')
        
        # Adjust layout
        plt.tight_layout()
        
        # Save or show
        if save_path:
            plt.savefig(save_path)
            print(f"Plot saved to {save_path}")
        else:
            plt.show()


def main():
    """Main function to demonstrate usage"""
    
    # Create threat intelligence object
    ti = ThreatIntelligence()
    
    # Create IOC extractor
    extractor = IOCExtractor()
    
    # Register some feeds
    ti.add_feed(
        name="AlienVault OTX",
        url="https://otx.alienvault.com/api/v1/pulses/subscribed",
        ioc_types=["ipv4", "domain", "url", "md5", "sha1", "sha256"]
    )
    
    ti.add_feed(
        name="PhishTank",
        url="http://data.phishtank.com/data/online-valid.json",
        ioc_types=["url", "domain"]
    )
    
    ti.add_feed(
        name="Abuse.ch URLhaus",
        url="https://urlhaus.abuse.ch/downloads/csv/",
        ioc_types=["url", "ipv4", "domain"]
    )
    
    ti.add_feed(
        name="EmergingThreats",
        url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        ioc_types=["ipv4"]
    )
    
    # Note: The above URLs might require API keys or have usage restrictions
    # For actual implementation, you should check the documentation of each feed
    
    # Create feed processor
    processor = FeedProcessor(ti, extractor)
    
    # Process feeds
    # In a real implementation, you would handle the API keys and rate limits
    # processor.process_all_feeds()
    
    # For demonstration, let's add some sample IOCs
    sample_text = """
    Threat actors have been observed using the malicious domain evil-malware.com
    to distribute ransomware. The attack infrastructure includes IP addresses
    192.168.1.100 and 203.0.113.42. Malware samples have been identified with the
    following hashes: 
    MD5: d41d8cd98f00b204e9800998ecf8427e
    SHA-1: da39a3ee5e6b4b0d3255bfef95601890afd80709
    
    Victims receive phishing emails from fake@malicious-domain.com with links to
    hxxps://malware-delivery.net/payload.exe
    
    CVE-2023-1234 is being actively exploited in these attacks.
    """
    
    # Extract IOCs from sample text
    sample_iocs = extractor.extract_from_text(sample_text, "Sample Data")
    
    # Add to threat intelligence
    for ioc in sample_iocs:
        ti.add_ioc(ioc)
    
    # Analyze trends
    analyzer = TrendAnalyzer(ti)
    trends = analyzer.analyze()
    
    # Print summary
    print(f"\nExtracted {len(ti.iocs)} IOCs:")
    for ioc_type, count in trends["ioc_types"].items():
        print(f"  - {ioc_type}: {count}")
    
    print("\nTop topics:")
    for topic, count in list(trends["topics"].items())[:5]:
        print(f"  - {topic}: {count}")
    
    # Create visualizer
    visualizer = Visualizer(ti)
    
    # Create visualizations
    # visualizer.plot_ioc_types()
    # visualizer.plot_confidence_distribution()
    
    # Save results
    ti.save_to_file("threat_intelligence.json")
    
    print("\nDone. Results saved to threat_intelligence.json")


if __name__ == "__main__":
    main()