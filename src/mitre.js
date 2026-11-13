// MITRE ATT&CK techniques that phishing findings map to.
export const TECHNIQUES = {
  T1566: { name: "Phishing", tactic: "Initial Access" },
  "T1566.001": { name: "Spearphishing Attachment", tactic: "Initial Access" },
  "T1566.002": { name: "Spearphishing Link", tactic: "Initial Access" },
  "T1598.003": { name: "Spearphishing Link (credential harvesting)", tactic: "Reconnaissance" },
  "T1656": { name: "Impersonation", tactic: "Defense Evasion" },
  "T1036": { name: "Masquerading", tactic: "Defense Evasion" },
  "T1036.007": { name: "Double File Extension", tactic: "Defense Evasion" },
  "T1036.002": { name: "Right-to-Left Override", tactic: "Defense Evasion" },
  "T1027": { name: "Obfuscated Files or Information", tactic: "Defense Evasion" },
  "T1027.006": { name: "HTML Smuggling", tactic: "Defense Evasion" },
  "T1553.005": { name: "Mark-of-the-Web Bypass", tactic: "Defense Evasion" },
  "T1221": { name: "Template Injection", tactic: "Defense Evasion" },
  "T1204.001": { name: "User Execution: Malicious Link", tactic: "Execution" },
  "T1204.002": { name: "User Execution: Malicious File", tactic: "Execution" },
  "T1059.005": { name: "Visual Basic (macros)", tactic: "Execution" },
  "T1059.007": { name: "JavaScript", tactic: "Execution" },
  "T1056.003": { name: "Web Portal Capture", tactic: "Credential Access" },
  "T1583.001": { name: "Acquire Infrastructure: Domains", tactic: "Resource Development" },
  "T1584": { name: "Compromise Infrastructure", tactic: "Resource Development" },
  "T1585.002": { name: "Establish Accounts: Email Accounts", tactic: "Resource Development" },
  "T1608.005": { name: "Stage Capabilities: Link Target", tactic: "Resource Development" },
  "T1534": { name: "Internal Spearphishing", tactic: "Lateral Movement" },
  "T1657": { name: "Financial Theft", tactic: "Impact" },
};

export function techniqueUrl(id) {
  return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
}

export function describe(id) {
  const t = TECHNIQUES[id];
  return t ? { id, ...t, url: techniqueUrl(id) } : { id, name: id, tactic: "", url: techniqueUrl(id) };
}
