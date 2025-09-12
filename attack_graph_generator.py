import json
import textwrap
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import matplotlib.patches as patches
import argparse
import sys

class AttackGraphGenerator:
    def __init__(self):
        # Define MITRE techniques relevant to different assets
        self.mitre_database = {
            "initial_access": {
                "T1190": "Exploit Public-Facing Application",
                "T1078": "Valid Accounts", 
                "T1078.004": "Cloud Accounts",
                "T1566": "Phishing",
                "T1566.001": "Spearfishing Attachment",
                "T1195": "Supply Chain Compromise",
                "T1195.002": "Compromise Software Supply Chain",
                "T1200": "Hardware Additions"
            },
            "execution": {
                "T1059.001": "PowerShell",
                "T1059.007": "JavaScript",
                "T1059.003": "Windows Command Shell",
                "T1072": "Software Deployment Tools"
            },
            "persistence": {
                "T1543.003": "Windows Service",
                "T1136": "Create Account",
                "T1078": "Valid Accounts"
            },
            "privilege_escalation": {
                "T1068": "Exploitation for Privilege Escalation"
            },
            "defense_evasion": {
                "T1562.001": "Disable or Modify Tools"
            },
            "credential_access": {
                "T1003": "OS Credential Dumping",
                "T1003.001": "LSASS Memory",
                "T1006": "Direct Volume Access",
                "T1552.001": "Credentials In Files",
                "T1552.004": "Private Keys"
            },
            "discovery": {
                "T1057": "Process Discovery",
                "T1069": "Permission Groups Discovery",
                "T1049": "System Network Connections Discovery",
                "T1083": "File and Directory Discovery"
            },
            "collection": {
                "T1005": "Data from Local System",
                "T1025": "Data from Removable Media",
                "T1530": "Data from Cloud Storage",
                "T1213.002": "Data from Information Repositories"
            },
            "exfiltration": {
                "T1041": "Exfiltration Over C2 Channel"
            }
        }

        # Extend MITRE techniques used for Web Application Integrity scenarios
        self.mitre_database.update({
            "impact": {
                "T1491": "Defacement",
                "T1491.001": "Internal Defacement",
                "T1491.002": "External Defacement",
                "T1565": "Data Manipulation",
                "T1565.001": "Stored Data Manipulation",
                "T1565.002": "Transmitted Data Manipulation",
                "T1565.003": "Runtime Data Manipulation"
            },
            "persistence_web": {
                "T1505": "Server Software Component",
                "T1505.003": "Web Shell"
            },
            "command_and_control": {
                "T1105": "Ingress Tool Transfer"
            },
            "credential_access_web": {
                "T1606": "Forge Web Credentials",
                "T1606.001": "Web Cookies",
                "T1606.002": "SAML Tokens",
                "T1606.003": "OAuth Tokens",
                "T1110.003": "Password Spraying"
            },
            "modify_auth": {
                "T1556": "Modify Authentication Process"
            },
            "collection_web": {
                "T1539": "Steal Web Session Cookie"
            },
            "credential_discovery": {
                "T1557": "Adversary-in-the-Middle"
            }
        })
        
        # Define attack path templates for databases
        self.database_attack_paths = {
            "sql_injection": {
                "name": "SQL Injection Attack Flow",
                "techniques": ["T1190", "T1059.007", "T1057", "T1005"],
                "descriptions": [
                    "Attacker exploits SQL injection vulnerability in web app",
                    "Execution of SQL injection queries via web application", 
                    "Enumerate database structure and tables",
                    "Extract sensitive data from database tables"
                ],
                "description": "Attack flow demonstrating how SQL injections can lead to the breach of confidentiality pertaining sensitive corporate and customer information"
            },
            "credential_theft": {
                "name": "Credential Theft Path",
                "techniques": ["T1566.001", "T1059.001", "T1006", "T1078", "T1003.001", "T1005"],
                "descriptions": [
                    "Phishing email with malicious Excel Macro",
                    "Macro executes macro payload onto the system",
                    "Uses stolen DBA credentials",
                    "Valid accounts for lateral movement",
                    "Dump credentials from computers memory taking advantage of the LSASS",
                    "Access database files directly"
                ],
                "description": "Multi-stage credential theft attack targeting database administrators"
            },
            "insider_threat": {
                "name": "Insider Threat Path", 
                "techniques": ["T1078.004", "T1069", "T1530"],
                "descriptions": [
                    "Malicious insider uses legitimate cloud access",
                    "Identify database access permissions", 
                    "Access hosted database backups"
                ],
                "description": "Malicious insider with legitimate access exploiting cloud database backups"
            },
            "supply_chain": {
                "name": "Supply Chain Attack Path",
                "techniques": ["T1195.002", "T1072", "T1543.003", "T1562.001", "T1005"],
                "descriptions": [
                    "Compromised database management tool update",
                    "Malicious update deployed enterprise-wide",  
                    "Install persistent backdoor service",
                    "Disable database audit logging",
                    "Direct database file access"
                ],
                "description": "Supply chain compromise targeting database management tools"
            },
            "backup_exploit": {
                "name": "Backup Exploitation Path",
                "techniques": ["T1190", "T1552.001", "T1552.004", "T1005", "T1041", "T1083"],
                "descriptions": [
                    "Exploit backup management interface",
                    "Find database credentials in backup configs",
                    "Extract encryption keys for the backup files", 
                    "Access and decrypt stolen database backups",
                    "Exfiltrate high-value database backup over encrypted channel",
                    "Enumerate databases and application files other backups that can have their data be exfiltrated"
                ],
                "description": "Multi-stage attack targeting database backup systems with conditional exfiltration"
            },
            "physical_access": {
                "name": "Physical Access Path",
                "techniques": ["T1200", "T1059.003", "T1068", "T1057", "T1025"],
                "descriptions": [
                    "USB device with malware planted is injected in the victim's end device",
                    "Execute windows commands via USB autorun (Now mostly disabled since windows 7)",
                    "Exploits local vulnerability for admin rights", 
                    "Discovery of database processes and services that can be exploited after gaining admin rights",
                    "Copy/exfiltrate data from database to removable device (in this case the USB)"
                ],
                "description": "Shows how a attacker can use physical media to potentially gain access to database information by posing as an admin"
            }
        }

        # Define attack path templates for Database Integrity
        self.database_integrity_paths = {
            "sql_injection_tamper": {
                "name": "Exploit → SQL Injection → Stored Data Manipulation",
                "techniques": ["T1190", "T1059.007", "T1565.001", "T1562.001"],
                "descriptions": [
                    "Exploit vulnerable application endpoint connected to the database",
                    "Execute crafted SQL statements to reach modification primitives",
                    "Alter stored records, tables, or business-critical values",
                    "Disable or modify auditing/monitoring to conceal changes"
                ],
                "description": "Use SQL injection to manipulate database contents and evade detection"
            },
            "sproc_trigger_alteration": {
                "name": "Valid Accounts → PrivEsc → Alter Procedures/Triggers → Runtime Manipulation",
                "techniques": ["T1078", "T1068", "T1059.007", "T1565.003"],
                "descriptions": [
                    "Use valid database or OS credentials to gain foothold",
                    "Exploit local privilege escalation on DB host or platform",
                    "Modify stored procedures/triggers via SQL execution",
                    "Manipulate in-memory behavior of transactions and results"
                ],
                "description": "Abuse elevated access to alter procedural logic for integrity impact"
            },
            "insider_migration_abuse": {
                "name": "Cloud Account → CI/CD Deploy → Data Manipulation",
                "techniques": ["T1078.004", "T1072", "T1565.001"],
                "descriptions": [
                    "Use legitimate cloud/dev account with DB migration permissions",
                    "Deploy unauthorized migration or job through deployment tooling",
                    "Apply schema/data changes that alter authoritative records"
                ],
                "description": "Insider abuses deployment pipelines to push integrity-impacting DB changes"
            },
            "replication_tamper": {
                "name": "Valid Accounts → Replication Abuse → Transmitted Data Manipulation",
                "techniques": ["T1078", "T1565.002", "T1565.001"],
                "descriptions": [
                    "Authenticate to database replication or sync channels",
                    "Alter data-in-transit so replicas receive falsified updates",
                    "Ensure manipulated data persists in primary or downstream stores"
                ],
                "description": "Propagate tampered data through replication to poison downstream databases"
            },
            "backup_restore_poisoning": {
                "name": "Exploit Backup → Grab Secrets → Poisoned Restore → Stored Manipulation",
                "techniques": ["T1190", "T1552.001", "T1552.004", "T1072", "T1565.001"],
                "descriptions": [
                    "Exploit backup/maintenance interface for database",
                    "Locate credentials or sensitive configs in backup systems",
                    "Extract encryption keys for protected backup sets",
                    "Restore attacker-modified backups via admin tooling",
                    "Introduce falsified records through the restored datasets"
                ],
                "description": "Leverage backup systems to inject attacker-controlled data into production"
            },
            "log_and_audit_bypass": {
                "name": "Valid Accounts → Disable Audit → Manipulate → Re-enable",
                "techniques": ["T1078", "T1562.001", "T1565.001", "T1562.001"],
                "descriptions": [
                    "Use valid DB admin/operator account",
                    "Disable/modify audit and integrity checks",
                    "Perform targeted updates to critical records",
                    "Restore logging to normal to reduce suspicion"
                ],
                "description": "Silent manipulation by temporarily disabling controls and restoring them afterward"
            },
            "etl_pipeline_tampering": {
                "name": "Supply Chain → ETL Job Compromise → Data Manipulation",
                "techniques": ["T1195.002", "T1072", "T1565.001"],
                "descriptions": [
                    "Compromise ETL/ELT tool or its plugins in supply chain",
                    "Deploy modified job configurations or scripts",
                    "Write falsified outputs into database targets"
                ],
                "description": "Integrity impact via compromised data integration pipelines"
            },
            "physical_host_tamper": {
                "name": "Hardware Additions → Shell → PrivEsc → Direct Data Tamper",
                "techniques": ["T1200", "T1059.003", "T1068", "T1565.001"],
                "descriptions": [
                    "Introduce removable media or device on DB host",
                    "Execute commands through local shell",
                    "Escalate privileges on the host",
                    "Manipulate database contents via direct tooling or files"
                ],
                "description": "Local host access used to tamper with database contents"
            },
            "rogue_account_manipulation": {
                "name": "Create Account → Valid Accounts → Stored Manipulation",
                "techniques": ["T1136", "T1078", "T1565.001"],
                "descriptions": [
                    "Create backdoor or shared database account",
                    "Leverage valid account to access write paths",
                    "Modify stored data in sensitive tables"
                ],
                "description": "Persistence through rogue accounts used to alter data over time"
            },
            "webshell_db_modification": {
                "name": "Exploit → Web Shell on App Host → SQL Modify",
                "techniques": ["T1190", "T1105", "T1505.003", "T1059.007", "T1565.001"],
                "descriptions": [
                    "Exploit public-facing application",
                    "Transfer web shell to the application server",
                    "Maintain web shell for command execution",
                    "Run SQL clients/ORM with elevated context",
                    "Modify stored records in application database"
                ],
                "description": "Use an app-host web shell to reach and tamper with the backing database"
            }
        }

        # Define attack path templates for Web Application Integrity
        self.webapp_attack_paths = {
            "web_defacement_webshell": {
                "name": "Exploit → Web Shell → External Defacement",
                "techniques": ["T1190", "T1105", "T1505.003", "T1491.002"],
                "descriptions": [
                    "Exploit vulnerability in public-facing web application",
                    "Upload or transfer malicious web shell to server",
                    "Establish persistent web shell for command execution",
                    "Modify public content and assets to deface site"
                ],
                "description": "External defacement by deploying a web shell after exploiting a public-facing application"
            },
            "stored_data_tampering": {
                "name": "Exploit/API Abuse → Stored Data Manipulation",
                "techniques": ["T1190", "T1059.007", "T1565.001"],
                "descriptions": [
                    "Exploit injection or logic flaws in web/API endpoints",
                    "Craft payloads to reach backend data modification paths",
                    "Alter stored application data (e.g., orders, balances, roles)"
                ],
                "description": "Tamper with application data at rest through vulnerable endpoints or injection flaws"
            },
            "admin_panel_abuse": {
                "name": "Valid Accounts → Admin Panel → Content Change",
                "techniques": ["T1078", "T1491.001", "T1565.001"],
                "descriptions": [
                    "Use stolen/valid credentials to access admin interface",
                    "Change internal site content or templates",
                    "Modify records and configuration to impact integrity"
                ],
                "description": "Use valid accounts to make unauthorized content/configuration changes via admin panels"
            },
            "credential_stuffing": {
                "name": "Password Spraying → Valid Accounts → Data Manipulation",
                "techniques": ["T1110.003", "T1078", "T1565.001"],
                "descriptions": [
                    "Spray common passwords across many accounts",
                    "Authenticate to privileged areas with a compromised account",
                    "Alter stored application data and records"
                ],
                "description": "Compromise weak credentials and abuse them to modify application data"
            },
            "supply_chain_defacement": {
                "name": "Supply Chain Compromise → Malicious Deploy → Defacement",
                "techniques": ["T1195.002", "T1072", "T1491.002"],
                "descriptions": [
                    "Compromise third-party dependency or build step",
                    "Use software deployment tooling to push tainted build",
                    "Deface external site content post-deployment"
                ],
                "description": "Integrity impact delivered via compromised dependencies and CI/CD pipelines"
            },
            "token_forgery_elevation": {
                "name": "Forge Web Credentials → Privileged Actions",
                "techniques": ["T1606.002", "T1565.001"],
                "descriptions": [
                    "Forge or manipulate SAML tokens to impersonate admins",
                    "Perform unauthorized changes to persistent data"
                ],
                "description": "Privilege elevation by forging web credentials to manipulate application state/data"
            },
            "cache_poisoning": {
                "name": "Exploit → Cache Poisoning → Transmitted Data Manipulation",
                "techniques": ["T1190", "T1565.002"],
                "descriptions": [
                    "Exploit request/response processing quirks",
                    "Poison CDN/reverse-proxy cache to serve attacker-controlled content"
                ],
                "description": "Manipulate content delivered to users via poisoned web caches"
            },
            "runtime_tampering": {
                "name": "Exploit → Runtime Data Manipulation",
                "techniques": ["T1190", "T1565.003"],
                "descriptions": [
                    "Exploit server-side template/deserialization flaw",
                    "Tamper with in-memory variables and responses at runtime"
                ],
                "description": "In-memory modification of application behavior to impact integrity"
            },
            "api_abuse": {
                "name": "API Abuse → Modify Records",
                "techniques": ["T1190", "T1565.001"],
                "descriptions": [
                    "Abuse weak/missing authorization on API endpoints",
                    "Directly modify sensitive resources via API calls"
                ],
                "description": "Manipulate back-end resources through insecure APIs"
            },
            "insider_malicious_deploy": {
                "name": "Insider with Cloud Account → Malicious Deploy",
                "techniques": ["T1078.004", "T1072", "T1565.001"],
                "descriptions": [
                    "Use legitimate cloud/dev credentials",
                    "Push unauthorized configuration or code",
                    "Manipulate stored data and business rules"
                ],
                "description": "Insider abuses cloud/dev access to deploy integrity-impacting changes"
            },
            "webshell_data_tampering": {
                "name": "Exploit → Web Shell → Stored Data Manipulation",
                "techniques": ["T1190", "T1105", "T1505.003", "T1565.001"],
                "descriptions": [
                    "Exploit public-facing app to gain foothold",
                    "Transfer web shell to the server",
                    "Execute commands via web shell",
                    "Alter database records and application state"
                ],
                "description": "Post-exploitation data tampering through a persistent web shell"
            },
            "third_party_widget_compromise": {
                "name": "Supply Chain Script → Content Manipulation",
                "techniques": ["T1195.002", "T1059.007", "T1491.002"],
                "descriptions": [
                    "Compromise third-party widgets/analytics scripts",
                    "Inject malicious client-side script into pages",
                    "Modify rendered content for external users"
                ],
                "description": "Integrity impact via compromised third-party web assets"
            },
            "auth_process_tamper": {
                "name": "Exploit → Modify Authentication Process → Data Tampering",
                "techniques": ["T1190", "T1556", "T1565.001"],
                "descriptions": [
                    "Exploit app flaw to gain code/config access",
                    "Alter authentication/authorization logic",
                    "Perform unauthorized changes to stored data"
                ],
                "description": "Tamper with app auth flows to enable persistent unauthorized changes"
            }
        }

        # Define attack path templates for Web Application Confidentiality
        self.webapp_confidentiality_paths = {
            "sql_injection_dump": {
                "name": "Exploit → SQLi/API → Data Exfil",
                "techniques": ["T1190", "T1059.007", "T1005", "T1041"],
                "descriptions": [
                    "Exploit public-facing app or API",
                    "Inject SQL/client-side payloads to extract data",
                    "Collect sensitive data from application/backend",
                    "Exfiltrate data over established C2 channel"
                ],
                "description": "Data theft via exploitation of web endpoints and injection vulnerabilities"
            },
            "session_hijack": {
                "name": "AitM/Steal Cookies → Valid Session",
                "techniques": ["T1557", "T1539", "T1078"],
                "descriptions": [
                    "Intercept traffic to capture session artifacts",
                    "Steal session cookies via AitM/script injection",
                    "Reuse valid session to access sensitive data"
                ],
                "description": "Use stolen session material to read protected information"
            },
            "token_forgery_data_access": {
                "name": "Forge Web Credentials → Read Data",
                "techniques": ["T1606.002", "T1078", "T1005"],
                "descriptions": [
                    "Forge SAML tokens to impersonate privileged users",
                    "Leverage access to protected areas",
                    "Collect sensitive data available to the role"
                ],
                "description": "Abuse forged web credentials to access confidential data"
            },
            "supply_chain_steal": {
                "name": "Supply Chain → Malicious Script → Harvest",
                "techniques": ["T1195.002", "T1059.007", "T1005", "T1041"],
                "descriptions": [
                    "Compromise third-party dependency or CDN script",
                    "Inject client-side code to skim or read data",
                    "Collect credentials/PII/payment data",
                    "Exfiltrate harvested data"
                ],
                "description": "Magecart-style client-side data theft via tainted supply chain"
            },
            "valid_accounts_browse": {
                "name": "Valid Accounts → Unauthorized Browsing",
                "techniques": ["T1078", "T1005"],
                "descriptions": [
                    "Use stolen/weak credentials to log in",
                    "Browse and collect sensitive information"
                ],
                "description": "Confidentiality loss by abusing valid accounts to read data"
            },
            "backup_endpoint_leak": {
                "name": "Exposed Backups/Endpoints → Data Exfil",
                "techniques": ["T1190", "T1083", "T1041"],
                "descriptions": [
                    "Exploit or discover exposed backup endpoints",
                    "Enumerate files and directories for sensitive artifacts",
                    "Exfiltrate accessible data over network"
                ],
                "description": "Leaking confidential data from misconfigured/exposed web storage"
            }
        }

    def generate_attack_graph(self, asset_type="database", security_property="confidentiality", selected_paths=None):
        """Generate attack graph for specified asset and security property"""
        
        print(f"Generating attack graph for {asset_type} - {security_property}")
        
        if asset_type == "database":
            if security_property == "confidentiality":
                return self.generate_database_confidentiality_graph(selected_paths)
            elif security_property == "integrity":
                return self.generate_database_integrity_graph(selected_paths)
            elif security_property == "availability":
                return self.generate_database_availability_graph()
        elif asset_type == "web_application":
            if security_property == "integrity":
                return self.generate_webapp_integrity_graph(selected_paths)
            elif security_property == "confidentiality":
                return self.generate_webapp_confidentiality_graph(selected_paths)
        
        # Add more asset types later
        else:
            print(f"Asset type '{asset_type}' not yet implemented")
            return None

    def _build_graph_from_paths(self, paths_dict, target_label, asset_type, security_property, selected_paths=None):
        """Generic builder for attack graphs based on a provided paths dictionary"""
        if selected_paths is None:
            selected_paths = list(paths_dict.keys())

        G = nx.DiGraph()
        G.graph['asset_type'] = asset_type
        G.graph['security_property'] = security_property
        G.graph['target_label'] = target_label

        # Add target node
        G.add_node(target_label, node_type="target")

        # Add only selected attack paths
        for path_id in selected_paths:
            if path_id not in paths_dict:
                continue

            path_info = paths_dict[path_id]
            prev_node = None
            for i, technique_id in enumerate(path_info["techniques"]):
                technique_name = self.get_technique_name(technique_id)
                node_id = f"{path_id}_{technique_id}_{i+1}"

                step_description = ""
                if "descriptions" in path_info and i < len(path_info["descriptions"]):
                    step_description = path_info["descriptions"][i]

                G.add_node(
                    node_id,
                    technique_id=technique_id,
                    technique_name=technique_name,
                    step_description=step_description,
                    path=path_info["name"],
                    node_type="technique",
                    step_number=i + 1
                )

                if prev_node:
                    G.add_edge(prev_node, node_id)
                prev_node = node_id

            if prev_node:
                G.add_edge(prev_node, target_label)

        return G

    def generate_database_confidentiality_graph(self, selected_paths=None):
        """Generate graph specifically for database confidentiality attacks"""
        return self._build_graph_from_paths(
            paths_dict=self.database_attack_paths,
            target_label="Database Confidentiality Breach",
            asset_type="database",
            security_property="confidentiality",
            selected_paths=selected_paths
        )

    def get_technique_name(self, technique_id):
        """Get technique name from ID"""
        for category, techniques in self.mitre_database.items():
            if technique_id in techniques:
                return techniques[technique_id]
        return "Unknown Technique"

    def visualize_graph(self, G, filename="attack_graph.png", selected_paths=None, label_mode="short", hide_legend=False, compact=False):
        """Visualize the attack graph"""
        
        # Larger canvas for dense graphs
        plt.figure(figsize=(26, 16))
        ax = plt.gca()
        
        # Set title based on graph metadata
        asset_type = G.graph.get('asset_type', 'asset').replace('_', ' ').title()
        security_property = G.graph.get('security_property', '').title()
        target_label = G.graph.get('target_label', 'Target')
        
        # Derive number of total paths present in graph
        paths_in_graph = set()
        for node, data in G.nodes(data=True):
            if data.get('node_type') == 'technique':
                path_name = data.get('path')
                if path_name:
                    paths_in_graph.add(path_name)
        total_paths = len(paths_in_graph)

        if selected_paths and total_paths > 0 and len(selected_paths) < total_paths:
            if len(selected_paths) == 1:
                only_path_name = next(iter(paths_in_graph))
                title = f'{asset_type} Attack Graph\n{only_path_name} → {security_property}'
            else:
                title = f'{asset_type} Attack Graph\nSelected Paths ({len(selected_paths)}) → {security_property}'
        else:
            title = f'Auto-Generated {asset_type} Attack Graph\nPaths to {security_property}'
            
        plt.title(title, fontsize=20, fontweight='bold')
        
        # Use hierarchical layout
        pos = self.calculate_positions(G, compact=compact)
        
        # Color scheme for different paths (database + webapp)
        path_colors = {
            # Database confidentiality
            "SQL Injection Attack Flow": "#3498db",
            "Credential Theft Path": "#2ecc71", 
            "Insider Threat Path": "#f39c12",
            "Supply Chain Attack Path": "#e74c3c",
            "Backup Exploitation Path": "#9b59b6",
            "Physical Access Path": "#1abc9c",
            # Database integrity
            "Exploit → SQL Injection → Stored Data Manipulation": "#1f77b4",
            "Valid Accounts → PrivEsc → Alter Procedures/Triggers → Runtime Manipulation": "#ff7f0e",
            "Cloud Account → CI/CD Deploy → Data Manipulation": "#2ca02c",
            "Valid Accounts → Replication Abuse → Transmitted Data Manipulation": "#d62728",
            "Exploit Backup → Grab Secrets → Poisoned Restore → Stored Manipulation": "#9467bd",
            "Valid Accounts → Disable Audit → Manipulate → Re-enable": "#8c564b",
            "Supply Chain → ETL Job Compromise → Data Manipulation": "#e377c2",
            "Hardware Additions → Shell → PrivEsc → Direct Data Tamper": "#7f7f7f",
            "Create Account → Valid Accounts → Stored Manipulation": "#bcbd22",
            "Exploit → Web Shell on App Host → SQL Modify": "#17becf",
            # Web application integrity
            "Exploit → Web Shell → External Defacement": "#d35400",
            "Exploit/API Abuse → Stored Data Manipulation": "#8e44ad",
            "Valid Accounts → Admin Panel → Content Change": "#16a085",
            "Password Spraying → Valid Accounts → Data Manipulation": "#2c3e50",
            "Supply Chain Compromise → Malicious Deploy → Defacement": "#c0392b",
            "Forge Web Credentials → Privileged Actions": "#7f8c8d",
            "Exploit → Cache Poisoning → Transmitted Data Manipulation": "#2980b9",
            "Exploit → Runtime Data Manipulation": "#27ae60",
            "API Abuse → Modify Records": "#e67e22",
            "Insider with Cloud Account → Malicious Deploy": "#9b59b6",
            "Exploit → Web Shell → Stored Data Manipulation": "#34495e",
            "Supply Chain Script → Content Manipulation": "#e74c3c",
            "Exploit → Modify Authentication Process → Data Tampering": "#8e44ad"
        }
        
        # Draw nodes
        for node, data in G.nodes(data=True):
            if data.get('node_type') == 'target':
                # Draw target node
                nx.draw_networkx_nodes(G, pos, [node], 
                                     node_color='#ff4444',
                                     node_size=3000,
                                     node_shape='h')  # hexagon
            else:
                # Draw technique nodes
                path = data.get('path', '')
                color = path_colors.get(path, '#95a5a6')
                nx.draw_networkx_nodes(G, pos, [node],
                                     node_color=color,
                                     node_size=2000,
                                     node_shape='s')  # square
        
        # Draw edges
        nx.draw_networkx_edges(G, pos, edge_color='gray', 
                             arrows=True, arrowsize=20, 
                             arrowstyle='->', width=2)
        
        # Add labels with descriptions (no truncation; wrap instead)
        labels = {}
        for node, data in G.nodes(data=True):
            if data.get('node_type') == 'target':
                labels[node] = node
            else:
                technique_id = data.get('technique_id', '')
                technique_name = data.get('technique_name', '')
                step_description = data.get('step_description', '')
                step_number = data.get('step_number', '')
                
                def wrap(text, width):
                    return "\n".join(textwrap.wrap(text, width=width)) if text else ""

                if step_number:
                    if label_mode == "id":
                        labels[node] = f"{step_number}. {technique_id}"
                    elif label_mode == "name":
                        labels[node] = f"{step_number}. {technique_id}:\n{wrap(technique_name, 28)}"
                    elif label_mode == "full":
                        content = step_description if step_description else technique_name
                        wrap_width = 60 if not compact else 46
                        labels[node] = f"{step_number}. {technique_id}:\n{wrap(content, wrap_width)}"
                    else:  # short
                        content = step_description if step_description else technique_name
                        wrap_width = 32 if compact else 38
                        labels[node] = f"{step_number}. {technique_id}:\n{wrap(content, wrap_width)}"
                else:
                    labels[node] = f"{technique_id}:\n{technique_name}" if technique_name else technique_id
        
        font_size = 7 if compact else 8
        nx.draw_networkx_labels(G, pos, labels, font_size=font_size)
        
        # Add legend - only for paths actually present in the graph
        legend_elements = []
        paths_in_graph = set()
        for node, data in G.nodes(data=True):
            if data.get('node_type') == 'technique':
                path_name = data.get('path')
                if path_name:
                    paths_in_graph.add(path_name)

        if not hide_legend:
            for path_name in paths_in_graph:
                if path_name in path_colors:
                    color = path_colors[path_name]
                    legend_elements.append(plt.Line2D([0], [0], marker='s', color='w', 
                                                    markerfacecolor=color, markersize=10,
                                                    label=path_name))
            if legend_elements:
                plt.legend(handles=legend_elements, loc='upper left', fontsize=10)
        
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.show()
        
        return filename

    def calculate_positions(self, G, compact=False):
        """Calculate node positions for visualization"""
        # Get paths
        paths = {}
        for node, data in G.nodes(data=True):
            if data.get('node_type') == 'technique':
                path = data.get('path')
                if path not in paths:
                    paths[path] = []
                paths[path].append(node)
        
        # Position nodes
        pos = {}
        
        # Target at bottom center
        target_nodes = [n for n, d in G.nodes(data=True) if d.get('node_type') == 'target']
        if target_nodes:
            pos[target_nodes[0]] = (0, 0)
        
        # Arrange paths in columns
        num_paths = len(paths)
        x_spacing = 6 if not compact else 5
        x_start = -(num_paths - 1) * x_spacing / 2
        
        for i, (path_name, nodes) in enumerate(paths.items()):
            x = x_start + i * x_spacing
            # Sort nodes by their order in the path
            sorted_nodes = sorted(nodes, key=lambda n: self.get_node_depth(G, n))
            
            for j, node in enumerate(sorted_nodes):
                y = (j + 1) * (2.5 if not compact else 2.2)
                pos[node] = (x, y)
        
        return pos

    def get_node_depth(self, G, node):
        """Get the depth of a node from the target"""
        # Simple BFS to find depth
        target_nodes = [n for n, d in G.nodes(data=True) if d.get('node_type') == 'target']
        if not target_nodes:
            return 0
        
        target = target_nodes[0]
        
        # Reverse the graph to measure from target
        G_rev = G.reverse()
        
        try:
            path = nx.shortest_path(G_rev, target, node)
            return len(path) - 1
        except:
            return 0

    def export_to_json(self, G, filename="attack_graph.json"):
        """Export graph to JSON format"""
        data = {
            "nodes": [],
            "edges": [],
            "metadata": {
                "asset_type": G.graph.get('asset_type', 'unknown'),
                "security_property": G.graph.get('security_property', 'unknown'),
                "generator": "AttackGraphGenerator v1.0"
            }
        }
        
        # Add nodes
        for node, attrs in G.nodes(data=True):
            data["nodes"].append({
                "id": node,
                "attributes": attrs
            })
        
        # Add edges
        for source, target in G.edges():
            data["edges"].append({
                "source": source,
                "target": target
            })
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        return filename

    def generate_database_integrity_graph(self, selected_paths=None):
        """Generate graph for database integrity attacks"""
        return self._build_graph_from_paths(
            paths_dict=self.database_integrity_paths,
            target_label="Database Integrity Compromise",
            asset_type="database",
            security_property="integrity",
            selected_paths=selected_paths
        )

    def generate_database_availability_graph(self):
        """Generate graph for database availability attacks (placeholder)"""
        print("Database availability attack graph not yet implemented")
        return None

    def generate_webapp_integrity_graph(self, selected_paths=None):
        """Generate graph for web application integrity attacks"""
        return self._build_graph_from_paths(
            paths_dict=self.webapp_attack_paths,
            target_label="Web Application Integrity Compromise",
            asset_type="web_application",
            security_property="integrity",
            selected_paths=selected_paths
        )

    def generate_webapp_confidentiality_graph(self, selected_paths=None):
        """Generate graph for web application confidentiality attacks"""
        return self._build_graph_from_paths(
            paths_dict=self.webapp_confidentiality_paths,
            target_label="Web Application Confidentiality Breach",
            asset_type="web_application",
            security_property="confidentiality",
            selected_paths=selected_paths
        )

    def get_available_options(self):
        """Get available asset types and security properties"""
        return {
            "asset_types": ["database", "web_application"],
            "security_properties": ["confidentiality", "integrity"]
        }


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Generate MITRE ATT&CK attack flow graphs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python attack_graph_generator.py                           # Interactive mode
  python attack_graph_generator.py -a database -s confidentiality  # All attacks
  python attack_graph_generator.py -a database -s confidentiality --attacks sql_injection insider_threat  # Specific attacks
  python attack_graph_generator.py --list                    # Show available options
        """
    )
    
    parser.add_argument('-a', '--asset', 
                       choices=['database', 'web_application'], 
                       help='Asset type to target')
    
    parser.add_argument('-s', '--security', 
                       choices=['confidentiality', 'integrity', 'availability'],
                       help='Security property to compromise')
    
    parser.add_argument('--list', action='store_true',
                       help='List available asset types and security properties')
    
    parser.add_argument('-o', '--output',
                       help='Output filename base (without extension)')
    parser.add_argument('--label-mode', choices=['short', 'id', 'name', 'full'], default='short',
                       help='Node label style for visualization')
    parser.add_argument('--hide-legend', action='store_true',
                       help='Hide legend to reduce clutter')
    parser.add_argument('--compact', action='store_true',
                       help='Compact spacing and smaller labels')
    
    parser.add_argument('--attacks', nargs='+',
                       choices=['sql_injection', 'credential_theft', 'insider_threat', 
                               'supply_chain', 'backup_exploit', 'physical_access',
                               # Web app integrity
                               'web_defacement_webshell', 'stored_data_tampering', 'admin_panel_abuse',
                               'credential_stuffing', 'supply_chain_defacement', 'token_forgery_elevation',
                               'cache_poisoning', 'runtime_tampering', 'api_abuse', 'insider_malicious_deploy',
                               'webshell_data_tampering', 'third_party_widget_compromise', 'auth_process_tamper',
                               # Database integrity
                               'sql_injection_tamper', 'sproc_trigger_alteration', 'insider_migration_abuse',
                               'replication_tamper', 'backup_restore_poisoning', 'log_and_audit_bypass',
                               'etl_pipeline_tampering', 'physical_host_tamper', 'rogue_account_manipulation',
                               'webshell_db_modification',
                               # Web app confidentiality
                               'sql_injection_dump', 'session_hijack', 'token_forgery_data_access',
                               'supply_chain_steal', 'valid_accounts_browse', 'backup_endpoint_leak'],
                       help='Specific attack paths to include (space-separated)')
    
    return parser.parse_args()


# Main execution
if __name__ == "__main__":
    # Parse command line arguments
    args = parse_arguments()
    
    # Create generator instance
    generator = AttackGraphGenerator()
    
    # Handle --list option
    if args.list:
        options = generator.get_available_options()
        print("=== Available Options ===")
        print("\nAsset Types:")
        for asset in options["asset_types"]:
            print(f"  • {asset}")
        print("\nSecurity Properties:")
        for prop in options["security_properties"]:
            status = "✓ Available" if prop in ["confidentiality", "integrity"] else "⏳ Coming Soon"
            print(f"  • {prop} ({status})")
        print()
        sys.exit(0)
    
    # Check if running in command line mode
    if args.asset and args.security:
        # Command line mode
        asset_type = args.asset
        security_property = args.security
        selected_paths = args.attacks  # Could be None (all attacks) or specific list
        
        # Validate that the combination is implemented
        implemented = (
            (asset_type == "database" and security_property in ["confidentiality", "integrity"]) or
            (asset_type == "web_application" and security_property in ["integrity", "confidentiality"])
        )
        if not implemented:
            print(f"Error: {asset_type} {security_property} attacks are not yet implemented.")
            print("Currently available combinations:")
            print("  • database + confidentiality")
            print("  • web_application + integrity")
            print("  • web_application + confidentiality")
            sys.exit(1)
        
        if selected_paths:
            # Determine correct paths dict
            if asset_type == "database" and security_property == "confidentiality":
                paths_dict = generator.database_attack_paths
            elif asset_type == "database" and security_property == "integrity":
                paths_dict = generator.database_integrity_paths
            elif asset_type == "web_application" and security_property == "integrity":
                paths_dict = generator.webapp_attack_paths
            elif asset_type == "web_application" and security_property == "confidentiality":
                paths_dict = generator.webapp_confidentiality_paths
            else:
                paths_dict = {}
            valid_selected = [p for p in selected_paths if p in paths_dict]
            selected_names = [paths_dict[path]['name'] for path in valid_selected]
            print(f"=== Generating {asset_type.title()} {security_property.title()} Attack Graph ===")
            print(f"Selected attacks: {', '.join(selected_names)}")
        else:
            print(f"=== Generating {asset_type.title()} {security_property.title()} Attack Graph ===")
            print("Including all available attack types")
        
    else:
        # Interactive mode
        print("=== MITRE ATT&CK Attack Flow Generator ===")
        print()
        
        # Get asset type
        print("Available asset types:")
        print("1. Database")
        print("2. Web Application")
        print("3. Network Infrastructure (coming soon)")
        print()
        
        while True:
            asset_choice = input("Select asset type (1-3): ").strip()
            if asset_choice == "1":
                asset_type = "database"
                break
            elif asset_choice == "2":
                asset_type = "web_application"
                break
            elif asset_choice == "3":
                print("This asset type is not yet implemented. Please select option 1 or 2.")
            else:
                print("Invalid choice. Please enter 1, 2, or 3.")
        
        print()
        print("Available security properties:")
        if asset_type == "database":
            print("1. Confidentiality")
            print("2. Integrity")
            print("3. Availability (coming soon)")
        elif asset_type == "web_application":
            print("1. Integrity")
            print("2. Confidentiality")
        print()
        
        while True:
            if asset_type == "database":
                security_choice = input("Select security property (1-3): ").strip()
                if security_choice == "1":
                    security_property = "confidentiality"
                    break
                elif security_choice == "2":
                    security_property = "integrity"
                    break
                elif security_choice == "3":
                    print("This security property is not yet implemented. Please select option 1 or 2.")
                else:
                    print("Invalid choice. Please enter 1, 2, or 3.")
            elif asset_type == "web_application":
                security_choice = input("Select security property (1-2): ").strip()
                if security_choice == "1":
                    security_property = "integrity"
                    break
                elif security_choice == "2":
                    security_property = "confidentiality"
                    break
                else:
                    print("Invalid choice. Please enter 1 or 2.")
        
        print()
        print("Available attack types:")
        print("=" * 50)
        
        # Choose correct attack paths dictionary based on selection
        if asset_type == "database" and security_property == "confidentiality":
            paths_dict = generator.database_attack_paths
        elif asset_type == "database" and security_property == "integrity":
            paths_dict = generator.database_integrity_paths
        elif asset_type == "web_application" and security_property == "integrity":
            paths_dict = generator.webapp_attack_paths
        elif asset_type == "web_application" and security_property == "confidentiality":
            paths_dict = generator.webapp_confidentiality_paths
        else:
            paths_dict = {}

        # Show available attacks
        attack_options = []
        for i, (path_id, path_info) in enumerate(paths_dict.items(), 1):
            attack_options.append(path_id)
            print(f"{i}. {path_info['name']}")
            print(f"   → {path_info['description']}")
            print(f"   → Attack Steps ({len(path_info['techniques'])} steps):")
            
            preview_steps = min(3, len(path_info['techniques']))
            for j in range(preview_steps):
                technique_id = path_info['techniques'][j]
                technique_name = generator.get_technique_name(technique_id)
                step_desc = ""
                if "descriptions" in path_info and j < len(path_info["descriptions"]):
                    step_desc = f" - {path_info['descriptions'][j]}"
                print(f"     {j+1}. {technique_id} ({technique_name}){step_desc}")
            
            if len(path_info['techniques']) > 3:
                print(f"     ... and {len(path_info['techniques']) - 3} more steps")
            print()
        
        print("Selection options:")
        print("• Enter numbers separated by commas (e.g., 1,3,5)")
        print("• Enter 'all' to include all attack types")
        print("• Press Enter to include all attack types")
        print("• Optional: type 'c' to toggle compact mode, 'l' to toggle legend, 'm' to change label mode")
        print()
        
        while True:
            choice = input("Select attack types: ").strip()
            
            if choice.lower() == 'all' or choice == '':
                selected_paths = list(paths_dict.keys())
                break
            else:
                try:
                    # Parse comma-separated numbers
                    indices = [int(x.strip()) - 1 for x in choice.split(',')]
                    selected_paths = []
                    
                    for idx in indices:
                        if 0 <= idx < len(attack_options):
                            selected_paths.append(attack_options[idx])
                        else:
                            raise ValueError(f"Invalid selection: {idx + 1}")
                    
                    if selected_paths:
                        break
                    else:
                        print("No valid selections made. Please try again.")
                except ValueError as e:
                    print(f"Invalid input: {e}")
                    print("Please enter numbers separated by commas (e.g., 1,3,5) or 'all'")
        
        print()
        selected_names = [paths_dict[path]['name'] for path in selected_paths]
        print(f"Selected attacks: {', '.join(selected_names)}")
        print(f"Generating {asset_type} {security_property} attack graph...")
    
    print()
    
    # Generate attack graph
    graph = generator.generate_attack_graph(asset_type, security_property, selected_paths)
    
    # Visualize and export the graph
    if graph:
        # Use custom output name if provided
        if args.output:
            filename_base = args.output
        else:
            filename_base = f"{asset_type}_{security_property}_attack_graph"
        
        print("Generating visualization...")
        generator.visualize_graph(
            graph,
            f"{filename_base}.png",
            selected_paths=selected_paths,
            label_mode=(args.label_mode if hasattr(args, 'label_mode') else 'short'),
            hide_legend=(args.hide_legend if hasattr(args, 'hide_legend') else False),
            compact=(args.compact if hasattr(args, 'compact') else False)
        )
        
        print("Exporting to JSON...")
        generator.export_to_json(graph, f"{filename_base}.json")
        
        print("\n" + "="*50)
        print("Graph generated successfully!")
        print("="*50)
        print(f"Asset Type: {asset_type.title()}")
        print(f"Security Property: {security_property.title()}")
        print(f"Total nodes: {graph.number_of_nodes()}")
        print(f"Total edges: {graph.number_of_edges()}")
        # Determine number of attack paths in the generated graph
        path_names_in_graph = set()
        for node, data in graph.nodes(data=True):
            if data.get('node_type') == 'technique':
                if data.get('path'):
                    path_names_in_graph.add(data.get('path'))
        print(f"Attack paths: {len(path_names_in_graph)}")
        print()
        print("Files generated:")
        print(f"  • {filename_base}.png (visualization)")
        print(f"  • {filename_base}.json (graph data)")
        print()
        
        # Show attack paths summary
        print("Attack Paths Included:")
        if asset_type == "database" and security_property == "confidentiality":
            paths_dict = generator.database_attack_paths
        elif asset_type == "database" and security_property == "integrity":
            paths_dict = generator.database_integrity_paths
        elif asset_type == "web_application" and security_property == "integrity":
            paths_dict = generator.webapp_attack_paths
        elif asset_type == "web_application" and security_property == "confidentiality":
            paths_dict = generator.webapp_confidentiality_paths
        else:
            paths_dict = {}

        paths_to_show = selected_paths if selected_paths else list(paths_dict.keys())
        for i, path_id in enumerate(paths_to_show, 1):
            if path_id in paths_dict:
                path_info = paths_dict[path_id]
                print(f"  {i}. {path_info['name']}")
                print(f"     → {path_info['description']}")
                print(f"     → Attack Steps:")
                
                # Show detailed step-by-step breakdown
                for j, technique_id in enumerate(path_info['techniques']):
                    technique_name = generator.get_technique_name(technique_id)
                    step_desc = ""
                    if "descriptions" in path_info and j < len(path_info["descriptions"]):
                        step_desc = f" - {path_info['descriptions'][j]}"
                    print(f"       {j+1}. {technique_id} ({technique_name}){step_desc}")
                print()
    else:
        print("Failed to generate attack graph. Please check your selections.")
        sys.exit(1)
