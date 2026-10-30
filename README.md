# wirehound
### Notes and instructions for executing WireHound

**Prerequisites:** The Python and Linux packages required for executing WireHound are listed in requirements.txt in the remote workspace.   
The following third-party Zeek packages also need to be installed: BACNET (sudo zkg install icsnpp-bacnet), S7COMM (sudo zkg install icsnpp-s7comm), sudo zkg install icsnpp-opcua-binary

**Module-1: system\_identifier (aka pre\_processing)**  
**—-----------------------------------------------------------------------------**

1. **Generating connectivity/network topology graph from PCAP file (dataset/test.pcap)**  
   **Command:** python scripts/pre\_processing/show\_topology.py \--input dataset/test.pcap \--out-prefix ./out/pre\_processing/topology  
2. **Generating textual description of the system and network topology**  
   python scripts/pre\_processing/describe\_network.py \--input out/pre\_processing/topology/consolidated\_topology/topology.gexf \--output out/pre\_processing/network\_description.txt  
3. **Generating Zeek logs in the form of SQL DB, along with the schema**  
   ./scripts/pre\_processing/zeek-policy-sweep.sh ./dataset/test.pcap ./out/pre\_processing/zeeklogs

**Module-2: anomaly\_identifier**  
**—-----------------------------------------------------------------------------**

1. **Prerequisite: ndr\_detection\_characteristics.md**  
   This is a generic artifact that I reused from one of my prior projects. I scraped the MITRE ATT\&CK and ATLAS matrices to get the list of all documented attack tactics and techniques, and prompted Claude to map the attack techniques to corresponding packet-, flow-, protocol-, IP-, and connection-level network characteristics. The output of this step is the file ./scripts/anomaly\_identifier/ndr\_detection\_characteristics.md  
2. **Generating the list of SQL queries**  
   **Prompt (executed using Claude Opus-5 MAX)::** The “schema” file contains the schema of the database created by Zeek after parsing a pcap file. The “ndr\_detection\_characteristics.md” file contains a list of traffic characteristics that characterize various adversarial tactics and techniques listed in the MITRE ATT\&CK and ATLAS matrices. For each characteristic listed, produce a set of SQL queries in the context of the schema that will help a network analyst identify possible adversarial behavior. In addition, for each table, list characteristics that might indicate adversarial or unusual system behavior, and provide the corresponding SQL queries. Feel free to join multiple tables if needed. For every query, select the timestamp (ts), wherever it is present, to track the occurrence of anomalous events. Store the output in a clearly formatted table (.xlsx file), where one column indicates characteristics and another indicates queries. If there are multiple queries for a characteristic, write each query in a separate row and duplicate the characteristic. Use sqlite3 dialect.   
   **Context:** ./out/pre\_processing/zeeklogs/schema, ./scripts/anomaly\_identifier/ndr\_detection\_characteristics.md  
   **Output:** ndr\_sqlQueries.xlsx (Place it in the path ./out/anomaly\_identifier/)  
3. **Executing SQL queries**  
   python scripts/anomaly\_identifier/run\_ndr\_queries.py \--xlsx out/anomaly\_identifier/ndr\_sqlQueries.xlsx \--db out/pre\_processing/zeeklogs/zeek.sqlite  \--out ./out/anomaly\_identifier/ndr\_sqlQueries\_Results.xlsx  
4. **Analysis of SQL query results**  
   python scripts/anomaly\_identifier/analyse\_with\_gemini.py \--xlsx out/ndr\_sqlQueryResults.xlsx \--gexf out/pre\_processing/topology/consolidated\_topology/topology.gexf \--txt out/pre\_processing/network\_description.txt \--out ./out/anomaly\_identifier/   


**Module-3: attack\_identifier**  
**—-----------------------------------------------------------------------------**  
**Prompt (executed using Claude Opus-5 MAX):** Act as a security analyst looking for suspicious activities/events in a given network.  
The file “topology.gexf” contains the communication paths and protocols used in the network. The file “sqlQueryAnalysis.xlsx” contains a list of SQL queries that help identify the presence of adversarial activities within the network, along with their results when executed on a database containing Zeek log files from the network under test, and a prediction of whether these results indicate adversarial activities. Based on the information in the attached files, arrange the adversarial activities in chronological order and construct detailed possible attack paths. Present the result in HTML format.  
**Context:** topology.gexf, sqlQueryAnalysis.xlsx  
**Output:** out/attack\_identifier/attack\_paths\_run.html

**Testing notes:**

1. Module-2\_Step-4 was executed thrice:  
   1. **Using Gemini-3.6-flash** Output: out/anomaly\_identifier/sqlQueryAnalysis\_1.xlsx  
   2. **Using Gemini-3.7-flash (round-1)** Output: out/anomaly\_identifier/sqlQueryAnalysis\_2.xlsx  
   3. **Using Gemini-3.7-flash (round-2)** Output: out/anomaly\_identifier/sqlQueryAnalysis\_3.xlsx

2. Module-3 was executed twice:  
   1. **Using out/anomaly\_identifier/sqlQueryAnalysis\_2.xlsx** Output: attack\_paths\_run1.html  
   2. **Using out/anomaly\_identifier/sqlQueryAnalysis\_3.xlsx** Output: attack\_paths\_run2.html

**Note:** The Python codes have been generated with the help of Claude Opus-5 MAX. However, I have manually tested and vetted them. The LLM prompts invoked from within the Python codes have been composed manually.
