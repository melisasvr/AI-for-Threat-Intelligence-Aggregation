# AI for Threat Intelligence Aggregation
This project uses Python and NLP techniques to extract and analyze Indicators of Compromise (IOCs) from open-source threat intelligence feeds.

## Overview
This tool aggregates data from various open-source threat intelligence feeds, processes the data using Natural Language Processing (NLP) techniques, and extracts valuable IOCs and trends to help security analysts stay informed about emerging threats.

## Features
- **Multi-source feed integration**: Connects to multiple threat intelligence feeds
- **Automated IOC extraction**: Uses regex patterns and NLP to identify various IOC types
- **Context analysis**: Captures surrounding text for each IOC to provide context
- **Confidence scoring**: Assigns confidence scores to extracted IOCs
- **Trend analysis**: Identifies common themes and relationships between threats
- **Visualization**: Generates visual representations of threat data
- **Persistence**: Saves extracted data for offline analysis

## IOC Types Supported
- IPv4 and IPv6 addresses
- Domain names
- URLs
- Email addresses
- File hashes (MD5, SHA-1, SHA-256)
- Bitcoin addresses
- CVE identifiers

## Installation
1. Clone this repository:
   ```
   git clone https://your-repository-url/threat-intel-aggregator.git
   cd threat-intel-aggregator
   ```
2. Create a virtual environment and activate it:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```
4. Download required NLP models:
   ```
   python -m spacy download en_core_web_sm
   python -m nltk.downloader punkt stopwords wordnet
   ```

## Usage
Run the main script:
```
python threat_intel_aggregator.py
```
## Project Structure
The project consists of several Python classes with specific responsibilities:
- `IOC`: Data class representing an Indicator of Compromise
- `ThreatIntelligence`: Main class for storing and managing threat intelligence data
- `IOCExtractor`: Extracts IOCs from text using regular expressions and NLP
- `TrendAnalyzer`: Analyzes trends in collected threat data
- `FeedProcessor`: Handles different feed formats (JSON, CSV, plain text)
- `Visualizer`: Creates visualizations of threat intelligence data

## Next Steps and Extensions
Here are some ways you can extend the project:
### 1. Advanced NLP Features
- Implement topic modeling using algorithms like LDA or NMF to identify threat categories
- Use named entity recognition to identify threat actors and malware families
- Implement sentiment analysis to identify severity of threats
- Train a custom NER model to better identify security-specific entities

### 2. Feed Integration Enhancements
- Add authentication for feeds that require API keys
- Implement rate limiting to comply with feed restrictions
- Add support for STIX/TAXII feeds
- Create parsers for MISP, OpenCTI, and other threat intelligence platforms

### 3. Machine Learning Integration
- Train a classifier to reduce false positives
- Implement clustering to identify related campaigns
- Use anomaly detection to identify unusual patterns
- Implement YARA rule generation from extracted patterns

### 4. User Interface
- Build a web interface using Flask or Django
- Create a dashboard with real-time feeds
- Add user authentication and role-based access control
- Implement alerting for high-priority threats

### 5. Scalability Improvements
- Use a database (e.g., MongoDB or PostgreSQL) for efficient storage
- Implement multiprocessing for parallel feed processing
- Add support for distributed processing using Celery
- Containerize the application using Docker

## API Reference
### ThreatIntelligence
```
# Create a new ThreatIntelligence object
ti = ThreatIntelligence()
# Add a feed source
ti.add_feed(name="Feed Name", url="https://feed-url.com", ioc_types=["ipv4", "domain"])
# Add an IOC manually
from datetime import datetime
ioc = IOC(value="example.com", ioc_type="domain", source="manual", timestamp=datetime.now())
ti.add_ioc(ioc)
# Save data to a file
ti.save_to_file("output.json")
# Load data from a file
ti.load_from_file("output.json")
```
### IOCExtractor
```
# Create an extractor
extractor = IOCExtractor()
# Extract IOCs from text
text = "Malicious activity from 192.168.1.1 targeting example.com"
iocs = extractor.extract_from_text(text, source="report")
```
### TrendAnalyzer
```
# Create an analyzer
analyzer = TrendAnalyzer(ti)
# Analyze trends
trends = analyzer.analyze()
```
#### FeedProcessor
```
# Create a processor
processor = FeedProcessor(ti, extractor)
# Process all feeds
processor.process_all_feeds()
# Process a specific feed
processor.process_feed("Feed Name")
```
### Visualizer
```
# Create a visualizer
visualizer = Visualizer(ti)
# Create visualizations
visualizer.plot_ioc_types()
visualizer.plot_time_series()
visualizer.plot_confidence_distribution()
visualizer.plot_sources()
```
### Sample Requirements.txt
- requests>=2.28.1
- pandas>=1.5.0
- numpy>=1.23.3
- nltk>=3.7
- spacy>=3.4.1
- matplotlib>=3.6.0
- seaborn>=0.12.0

## License
- This project is licensed under the MIT License - see the LICENSE file for details.
## Contributing
- Contributions are welcome! Please feel free to submit a Pull Request.
## Acknowledgements
- AlienVault OTX
- PhishTank
- Abuse.ch
- Emerging Threats

## Disclaimer
- This tool is intended for security research and defense purposes only. Always ensure you have proper authorization before using it against any systems or networks.
