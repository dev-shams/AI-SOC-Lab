const demoAlert = {
  id: "INC-001",
  index: "demo",
  time: "Jul 14, 2026 @ 12:41:16.550",
  timestamp: "2026-07-14T12:41:16.550+0000",
  agent: { id: "001", name: "WIN11-SOC-ENDPOINT", ip: "192.168.64.3" },
  rule: {
    id: "92027",
    level: 4,
    description: "Powershell process spawned powershell instance",
    mitreId: "T1059.001",
    mitreTactic: "Execution",
    mitreTechnique: "PowerShell",
    groups: ["sysmon", "sysmon_eid1_detections", "windows"],
  },
  event: {
    channel: "Microsoft-Windows-Sysmon/Operational",
    eventId: "1",
    provider: "Microsoft-Windows-Sysmon",
  },
  process: {
    image: "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    parentImage: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    commandLine:
      '"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command "Write-Output \'WAZUH-POWERSHELL-TEST-002\'; whoami; hostname"',
    user: "WIN11-SOC-ENDPO\\Shams",
  },
};

const emptyAlert = {
  id: "NO-CANDIDATES",
  index: "empty",
  timestamp: "",
  agent: { name: "No endpoint selected", ip: "" },
  rule: {
    id: "",
    level: 0,
    description: "No incident candidates found",
    mitreId: "",
    mitreTactic: "",
    mitreTechnique: "",
    groups: [],
  },
  event: {
    channel: "Wazuh alert triage",
    eventId: "",
    provider: "AI SOC",
    message: "Wazuh is live, but the current alerts look like normal Windows startup/background noise or lower-priority review items.",
  },
  process: {},
  triage: {
    status: "clear",
    score: 0,
    reason: "No strong suspicious indicator matched in the focused queue",
  },
};

let alerts = [];
let selectedAlert = demoAlert;
let surroundingEvents = [];
let alertSummary = {};
let currentProfile = "candidates";
let currentSection = "overview";
let alertMinutes = 1440;
let alertSearchTerm = "";
let isInvestigationOpen = false;
let isAnalyzing = false;
let aiStatus = { enabled: false, reason: "", model: "" };
let snapshot = null;
let isSnapshotMode = false;

const profileLabels = {
  candidates: "Incident candidates",
  review: "Needs review",
  raw: "Raw Wazuh logs",
  noise: "Suppressed noise",
};

const tableBody = document.querySelector("#alertTableBody");
const details = document.querySelector("#alertDetails");
const rawEventOutput = document.querySelector("#rawEventOutput");
const chatLog = document.querySelector("#chatLog");
const artifactOutput = document.querySelector("#artifactOutput");
const artifactStatus = document.querySelector("#artifactStatus");
const chatForm = document.querySelector("#chatForm");
const chatInput = document.querySelector("#chatInput");
const dataModeLabel = document.querySelector("#dataModeLabel");
const dataModeText = document.querySelector("#dataModeText");
const caseTitle = document.querySelector("#caseTitle");
const workspaceEyebrow = document.querySelector("#workspaceEyebrow");
const openAlertsMetric = document.querySelector("#openAlertsMetric");
const reviewAlertsMetric = document.querySelector("#reviewAlertsMetric");
const rawAlertsMetric = document.querySelector("#rawAlertsMetric");
const suppressedAlertsMetric = document.querySelector("#suppressedAlertsMetric");
const quickMetrics = document.querySelector(".metrics");
const severityBadge = document.querySelector("#severityBadge");
const queueModePill = document.querySelector("#queueModePill");
const queueTabs = document.querySelectorAll("[data-profile]");
const navItems = document.querySelectorAll(".nav-item[data-section]");
const overviewView = document.querySelector("#overviewView");
const alertsView = document.querySelector("#alertsView");
const analysisView = document.querySelector("#analysisView");
const sectionEyebrow = document.querySelector("#sectionEyebrow");
const sectionTitle = document.querySelector("#sectionTitle");
const sectionStatus = document.querySelector("#sectionStatus");
const sectionBody = document.querySelector("#sectionBody");
const overviewActiveAgents = document.querySelector("#overviewActiveAgents");
const overviewDisconnectedAgents = document.querySelector("#overviewDisconnectedAgents");
const overviewCriticalAlerts = document.querySelector("#overviewCriticalAlerts");
const overviewHighAlerts = document.querySelector("#overviewHighAlerts");
const overviewMediumAlerts = document.querySelector("#overviewMediumAlerts");
const overviewLowAlerts = document.querySelector("#overviewLowAlerts");
const overviewRecentList = document.querySelector("#overviewRecentList");
const workspace = document.querySelector(".workspace");
const alertSearchInput = document.querySelector("#alertSearchInput");
const alertTimeRange = document.querySelector("#alertTimeRange");
const clearAlertFilters = document.querySelector("#clearAlertFilters");
const alertCriticalCount = document.querySelector("#alertCriticalCount");
const alertHighCount = document.querySelector("#alertHighCount");
const alertMediumCount = document.querySelector("#alertMediumCount");
const alertLowCount = document.querySelector("#alertLowCount");
const alertTotalCount = document.querySelector("#alertTotalCount");
const topRulesList = document.querySelector("#topRulesList");
const topEndpointsList = document.querySelector("#topEndpointsList");
const alertDetailPanels = document.querySelectorAll("[data-alert-detail]");
const closeAlertInvestigation = document.querySelector("#closeAlertInvestigation");
const copyReportButton = document.querySelector("#copyReportButton");
const demoAnalyzeButton = document.querySelector("#demoAnalyzeButton");
const aiModeText = document.querySelector("#aiModeText");
const aiPanelPill = document.querySelector("#aiPanelPill");
const brandMode = document.querySelector("#brandMode");

const sectionMeta = {
  overview: {
    eyebrow: "Overview",
    title: "SOC Lab Overview",
    status: "Live overview",
  },
  alerts: {
    eyebrow: "Queue",
    title: "Alerts",
    status: "Live queue",
  },
  timeline: {
    eyebrow: "Timeline",
    title: "Investigation Timeline",
    status: "Evidence view",
  },
  mitre: {
    eyebrow: "MITRE ATT&CK",
    title: "Technique Mapping",
    status: "Mapped",
  },
  detections: {
    eyebrow: "Detection engineering",
    title: "Detection Logic",
    status: "Draft rule",
  },
  report: {
    eyebrow: "Incident report",
    title: "Case Writeup",
    status: "Draft",
  },
};

function alertTime(alert) {
  return alert.time || alert.timestamp || "Unknown";
}

function compactAlertTime(alert) {
  const value = alert.timestamp || alert.time;
  if (!value) return "Unknown";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(parsed);
}

function severityFor(alert) {
  const level = Number(alert.rule?.level || 0);
  if (level >= 15) return { key: "critical", label: "Critical" };
  if (level >= 12) return { key: "high", label: "High" };
  if (level >= 7) return { key: "medium", label: "Medium" };
  return { key: "low", label: "Low" };
}

function filteredAlerts() {
  const query = alertSearchTerm.trim().toLowerCase();
  if (!query) return alerts;
  return alerts.filter((alert) => {
    const fields = [
      alert.rule?.description,
      alert.rule?.id,
      alert.rule?.mitreId,
      alert.rule?.mitreTechnique,
      alert.rule?.mitreTactic,
      alert.agent?.name,
      alert.agent?.ip,
      alert.process?.user,
      alert.process?.image,
      alert.process?.parentImage,
      alert.process?.commandLine,
      alert.event?.channel,
      alert.event?.eventId,
      alert.triage?.status,
      alert.triage?.reason,
    ];
    return fields.some((field) => String(field || "").toLowerCase().includes(query));
  });
}

function endpoint(alert) {
  return alert.agent?.name || "Unknown endpoint";
}

function commandLine(alert) {
  return alert.process?.commandLine || alert.event?.message || "No command line available";
}

function mitreLabel(alert) {
  const id = alert.rule?.mitreId || "Unmapped";
  const technique = alert.rule?.mitreTechnique || "Technique unavailable";
  return `${id} - ${technique}`;
}

const mitreTechniqueNames = {
  "T1027": "Obfuscated Files or Information",
  "T1059.001": "PowerShell",
  "T1098": "Account Manipulation",
  "T1105": "Ingress Tool Transfer",
  "T1136.001": "Local Account",
};

function policyMitreIds(alert) {
  const policyIds = Array.isArray(alert.triage?.mitre) ? alert.triage.mitre : [];
  const wazuhId = alert.rule?.mitreId ? [alert.rule.mitreId] : [];
  return [...new Set([...wazuhId, ...policyIds].filter(Boolean))];
}

function mappedMitreLabels(alert) {
  const ids = policyMitreIds(alert);
  if (!ids.length) return ["Unmapped"];
  return ids.map((id) => {
    const technique =
      id === alert.rule?.mitreId
        ? alert.rule?.mitreTechnique || mitreTechniqueNames[id]
        : mitreTechniqueNames[id];
    return technique ? `${id} - ${technique}` : id;
  });
}

function decodedPowerShellCommand(alert) {
  const match = commandLine(alert).match(
    /-(?:EncodedCommand|enc)\s+["']?([A-Za-z0-9+/=]{8,})/i,
  );
  if (!match || typeof atob !== "function" || typeof TextDecoder !== "function") return "";

  try {
    const binary = atob(match[1]);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return new TextDecoder("utf-16le").decode(bytes).replace(/\0/g, "").trim();
  } catch {
    return "";
  }
}

function detectionProfile(alert) {
  const configured = alert.triage?.detection;
  if (configured && Object.keys(configured).length) return configured;

  const command = commandLine(alert).toLowerCase();
  if (command.includes("-encodedcommand") || command.includes(" -enc ")) {
    return {
      title: "PowerShell Encoded Command",
      image_endswith: "\\powershell.exe",
      command_line_any: ["-EncodedCommand", "-enc "],
      level: "high",
      false_positives: ["Legitimate encoded administration scripts"],
    };
  }

  return {
    title: alert.rule?.description || "Suspicious Process Creation",
    image_endswith: `\\${(alert.process?.image || "process.exe").split("\\").pop()}`,
    command_line_any: [],
    level: severityFor(alert).key,
    false_positives: ["Authorized administrator activity"],
  };
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function inlineMarkdown(text) {
  return escapeHtml(text)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[\s(])\*([^*\n]+)\*/g, "$1<em>$2</em>");
}

function renderMarkdownProse(source) {
  const lines = source.split("\n");
  const out = [];
  let paragraph = [];
  let listTag = "";
  let tableRows = [];

  const flushParagraph = () => {
    if (!paragraph.length) return;
    out.push(`<p>${inlineMarkdown(paragraph.join(" "))}</p>`);
    paragraph = [];
  };
  const flushList = () => {
    if (!listTag) return;
    out.push(`</${listTag}>`);
    listTag = "";
  };
  const flushTable = () => {
    if (!tableRows.length) return;
    const cellsFor = (row) => row.replace(/^\||\|$/g, "").split("|").map((cell) => cell.trim());
    const isDivider = (row) => /^[\s|:-]+$/.test(row);
    const header = isDivider(tableRows[1] || "") ? cellsFor(tableRows[0]) : null;
    const bodyRows = tableRows.slice(header ? 2 : 0).filter((row) => !isDivider(row));
    const head = header
      ? `<thead><tr>${header.map((cell) => `<th>${inlineMarkdown(cell)}</th>`).join("")}</tr></thead>`
      : "";
    const body = bodyRows
      .map((row) => `<tr>${cellsFor(row).map((cell) => `<td>${inlineMarkdown(cell)}</td>`).join("")}</tr>`)
      .join("");
    out.push(`<div class="md-table-wrap"><table class="md-table">${head}<tbody>${body}</tbody></table></div>`);
    tableRows = [];
  };

  lines.forEach((rawLine) => {
    const line = rawLine.trimEnd();

    if (/^\s*\|.*\|\s*$/.test(line)) {
      flushParagraph();
      flushList();
      tableRows.push(line.trim());
      return;
    }
    flushTable();

    if (!line.trim()) {
      flushParagraph();
      flushList();
      return;
    }

    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    if (heading) {
      flushParagraph();
      flushList();
      const level = Math.min(heading[1].length + 2, 6);
      out.push(`<h${level}>${inlineMarkdown(heading[2])}</h${level}>`);
      return;
    }

    if (/^\s*(---|___|\*\*\*)\s*$/.test(line)) {
      flushParagraph();
      flushList();
      out.push("<hr>");
      return;
    }

    const bullet = line.match(/^\s*[-*+]\s+(.*)$/);
    const numbered = line.match(/^\s*\d+[.)]\s+(.*)$/);
    if (bullet || numbered) {
      flushParagraph();
      const wanted = bullet ? "ul" : "ol";
      if (listTag !== wanted) {
        flushList();
        listTag = wanted;
        out.push(`<${wanted}>`);
      }
      out.push(`<li>${inlineMarkdown((bullet || numbered)[1])}</li>`);
      return;
    }

    flushList();
    paragraph.push(line.trim());
  });

  flushParagraph();
  flushList();
  flushTable();
  return out.join("");
}

function renderMarkdown(source) {
  return String(source ?? "")
    .split(/```/)
    .map((part, index) => {
      if (index % 2 === 0) return renderMarkdownProse(part);
      const newline = part.indexOf("\n");
      const language = newline === -1 ? "" : part.slice(0, newline).trim();
      const code = newline === -1 ? part : part.slice(newline + 1);
      const label = language ? ` data-lang="${escapeHtml(language)}"` : "";
      return `<pre class="md-code"${label}><code>${escapeHtml(code.replace(/\n+$/, ""))}</code></pre>`;
    })
    .join("");
}

function artifactTemplates(alert) {
  const contextSummary = surroundingEvents.length
    ? `Loaded ${surroundingEvents.length} surrounding events from Wazuh for the same endpoint.`
    : "Surrounding events have not been loaded yet.";
  const mitreMappings = mappedMitreLabels(alert);

  return {
  summary: `Executive Summary

Wazuh generated an alert on ${endpoint(alert)}. The alert matched rule ${alert.rule?.id || "unknown"}, "${alert.rule?.description || "No description"}", with rule level ${alert.rule?.level ?? "unknown"}.

The source event is ${alert.event?.channel || "unknown channel"} Event ID ${alert.event?.eventId || "unknown"}. The command or event text should be reviewed for execution behavior, unusual parent-child process relationships, and suspicious command-line switches.

Triage status: ${alert.triage?.status || "review"}.
Triage reason: ${alert.triage?.reason || "No triage reason available"}.

Assessment: This dashboard shows a live Wazuh alert. The AI assistant is in free demo mode, so treat this as an evidence-bound draft and validate in Wazuh before concluding compromise.

${contextSummary}`,

  timeline: `Timeline

Alert time:
${alertTime(alert)}

Source:
${alert.event?.channel || "Unknown source"} Event ID ${alert.event?.eventId || "unknown"}

Alert:
${alert.rule?.description || "No rule description"}

Command or event text:
${commandLine(alert)}

Context:
${contextSummary}`,

  mitre: `MITRE ATT&CK Mapping

Techniques:
${mitreMappings.map((mapping) => `- ${mapping}`).join("\n") || "- Not mapped"}

Tactic: ${alert.rule?.mitreTactic || "Not mapped by Wazuh"}

Why it maps:
These mappings combine Wazuh rule metadata with the matched local triage policy. Confirm that the event evidence supports each mapping before publishing the investigation.

Analyst note:
MITRE mapping describes behavior. It does not prove malicious intent by itself.`,

  response: `Response Plan

1. Confirm whether the PowerShell command was authorized.
2. Review parent and child process relationships.
3. Search PowerShell and Sysmon events around the alert time.
4. Review surrounding events for downloads, account changes, persistence, credential access, or outbound connections.
5. Escalate only if supporting suspicious evidence is found.

Current status:
${contextSummary}`,

  detection: `Detection Logic

Wazuh DQL:
${dqlFor(alert)}

Sigma draft:
${sigmaFor(alert)}`,
  };
}

function reportFor(alert) {
  const decodedCommand = decodedPowerShellCommand(alert);
  const decodedSection = decodedCommand
    ? `
## Decoded PowerShell Payload

\`\`\`powershell
${decodedCommand}
\`\`\`
`
    : "";
  return `# Incident Report: ${alert.rule?.description || "Wazuh Alert"}

## Summary

Wazuh generated an alert on ${endpoint(alert)}. The alert matched rule ${alert.rule?.id || "unknown"} with level ${alert.rule?.level ?? "unknown"}.

## Alert Details

- Triage: ${alert.triage?.status || "review"} - ${alert.triage?.reason || "No reason"}
- Endpoint: ${endpoint(alert)}
- Rule: ${alert.rule?.id || "unknown"}
- Description: ${alert.rule?.description || "No description"}
- Level: ${alert.rule?.level ?? "unknown"}
- Source: ${alert.event?.channel || "unknown"}
- Event ID: ${alert.event?.eventId || "unknown"}
- MITRE: ${mappedMitreLabels(alert).join(", ")}
- Tactic: ${alert.rule?.mitreTactic || "Not mapped"}

## Command Or Event Text

\`\`\`text
${commandLine(alert)}
\`\`\`
${decodedSection}

## Assessment

This report was generated by the free demo-mode AI assistant using live Wazuh alert fields. Validate all conclusions against Wazuh and endpoint evidence.

## Response

Validate user context, inspect related endpoint telemetry, review surrounding events, and escalate only if supporting suspicious evidence is found.`;
}

function dqlFor(alert) {
  const detection = detectionProfile(alert);
  const eventId = alert.event?.eventId || "1";
  const imageName = (detection.image_endswith || alert.process?.image || "process.exe")
    .split("\\")
    .pop();
  const commandTerms = (detection.command_line_any || []).map(
    (term) => `data.win.eventdata.commandLine: "*${String(term).trim()}*"`,
  );
  const commandClause =
    commandTerms.length > 1 ? `(${commandTerms.join(" or ")})` : commandTerms[0] || "";

  return [
    `data.win.system.eventID: ${eventId}`,
    `data.win.eventdata.image: "*${imageName}"`,
    commandClause,
  ]
    .filter(Boolean)
    .join(" and ");
}

function sigmaFor(alert) {
  const detection = detectionProfile(alert);
  const command = commandLine(alert);
  const imageEndsWith = detection.image_endswith || "\\process.exe";
  const commandTerms = detection.command_line_any || [];
  const commandSelection = commandTerms.length
    ? `  selection_command:
    CommandLine|contains:
${commandTerms.map((term) => `      - '${String(term).replace(/'/g, "''")}'`).join("\n")}
`
    : "";
  const condition = commandTerms.length
    ? "selection_image and selection_command"
    : "selection_image";
  const falsePositives = detection.false_positives || ["Authorized administrator activity"];
  const tags = policyMitreIds(alert).length
    ? policyMitreIds(alert)
    : [alert.rule?.mitreId || "T1059.001"];

  return `title: ${detection.title || "Suspicious Process Creation"}
id: e7f8a5be-48b2-4cc8-9a6d-2a61d45df502
status: experimental
description: Detects ${String(detection.title || "the investigated process behavior").toLowerCase()}.
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith: '${imageEndsWith.replace(/'/g, "''")}'
${commandSelection}  condition: ${condition}
fields:
  - Image
  - ParentImage
  - CommandLine
  - User
falsepositives:
${falsePositives.map((item) => `  - ${item}`).join("\n")}
level: ${detection.level || "medium"}
tags:
  - attack.execution
${tags.map((id) => `  - attack.${String(id).toLowerCase()}`).join("\n")}

# Evidence command line:
# ${command}`;
}

function fieldBlock(label, value) {
  return `
    <div class="field-block">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value || "Unavailable")}</strong>
    </div>
  `;
}

function codeBlock(label, value) {
  return `
    <div class="code-card">
      <div class="code-card-label">${escapeHtml(label)}</div>
      <pre tabindex="0">${escapeHtml(value || "Unavailable")}</pre>
    </div>
  `;
}

function renderTimelineSection(alert) {
  const contextText = surroundingEvents.length
    ? `${surroundingEvents.length} surrounding events loaded from Wazuh`
    : "Context loading or unavailable";
  const decodedCommand = decodedPowerShellCommand(alert);
  const decodedTimelineItem = decodedCommand
    ? `
      <li>
        <span class="timeline-dot"></span>
        <div>
          <h4>Encoded payload decoded</h4>
          <p>${escapeHtml(decodedCommand)}</p>
        </div>
      </li>
    `
    : "";
  return `
    <div class="section-summary">
      ${fieldBlock("Alert time", alertTime(alert))}
      ${fieldBlock("Endpoint", `${endpoint(alert)} (${alert.agent?.ip || "no IP"})`)}
      ${fieldBlock("Rule", `${alert.rule?.id || "unknown"} · ${alert.rule?.description || "No description"}`)}
      ${fieldBlock("Context", contextText)}
    </div>
    <ol class="timeline-list">
      <li>
        <span class="timeline-dot"></span>
        <div>
          <h4>Telemetry received</h4>
          <p>${escapeHtml(alert.event?.channel || "Unknown channel")} logged Event ID ${escapeHtml(alert.event?.eventId || "unknown")}.</p>
        </div>
      </li>
      <li>
        <span class="timeline-dot"></span>
        <div>
          <h4>Process activity observed</h4>
          <p>${escapeHtml(alert.process?.image || "Process image unavailable")}</p>
        </div>
      </li>
      <li>
        <span class="timeline-dot"></span>
        <div>
          <h4>Command line captured</h4>
          <p>${escapeHtml(commandLine(alert))}</p>
        </div>
      </li>
      ${decodedTimelineItem}
      <li>
        <span class="timeline-dot"></span>
        <div>
          <h4>Analyst triage</h4>
          <p>${escapeHtml(alert.triage?.reason || "No triage reason available")}</p>
        </div>
      </li>
    </ol>
  `;
}

function renderMitreSection(alert) {
  const mappings = mappedMitreLabels(alert);
  return `
    <div class="section-summary">
      ${fieldBlock("Primary technique", mappings[0])}
      ${fieldBlock("Policy mappings", mappings.join(", "))}
      ${fieldBlock("Tactic", alert.rule?.mitreTactic || "Not mapped")}
      ${fieldBlock("Rule level", alert.rule?.level ?? "Unknown")}
    </div>
    <div class="narrative-card">
      <h4>Why this mapping matters</h4>
      <p>The evidence maps to ${escapeHtml(mappings.join(" and "))}. Treat these mappings as behavior labels: they explain what the alert resembles, but do not prove malicious intent by themselves.</p>
    </div>
    <div class="narrative-card">
      <h4>Evidence to validate</h4>
      <p>Confirm the command line, parent process, user, and surrounding events. If the action was expected lab activity, document it as authorized simulation. If not, escalate and look for download, persistence, credential access, or outbound connection evidence.</p>
    </div>
  `;
}

function renderDetectionsSection(alert) {
  return `
    <div class="section-summary">
      ${fieldBlock("Detection source", alert.event?.channel || "Unknown")}
      ${fieldBlock("Event ID", alert.event?.eventId || "Unknown")}
      ${fieldBlock("Rule ID", alert.rule?.id || "Unknown")}
      ${fieldBlock("MITRE", mappedMitreLabels(alert).join(", "))}
    </div>
    <div class="split-grid">
      ${codeBlock("Wazuh DQL", dqlFor(alert))}
      ${codeBlock("Sigma draft", sigmaFor(alert))}
    </div>
  `;
}

function renderReportSection(alert) {
  return `
    <div class="section-summary">
      ${fieldBlock("Case", alert.rule?.description || "Wazuh alert")}
      ${fieldBlock("Endpoint", endpoint(alert))}
      ${fieldBlock("Triage", `${alert.triage?.status || "review"} · ${alert.triage?.reason || "No reason"}`)}
      ${fieldBlock("Generated from", "Live Wazuh fields")}
    </div>
    ${codeBlock("Markdown report", reportFor(alert))}
  `;
}

function renderSection(section = currentSection) {
  const meta = sectionMeta[section] || sectionMeta.alerts;
  if (section === "alerts" || section === "overview") return;
  sectionEyebrow.textContent = meta.eyebrow;
  sectionTitle.textContent = meta.title;
  sectionStatus.textContent = meta.status;

  if (section === "timeline") sectionBody.innerHTML = renderTimelineSection(selectedAlert);
  if (section === "mitre") sectionBody.innerHTML = renderMitreSection(selectedAlert);
  if (section === "detections") sectionBody.innerHTML = renderDetectionsSection(selectedAlert);
  if (section === "report") sectionBody.innerHTML = renderReportSection(selectedAlert);
}

function setSection(section) {
  currentSection = section;
  workspace.dataset.section = section;
  document.body.dataset.section = section;
  navItems.forEach((item) => item.classList.toggle("is-active", item.dataset.section === section));
  const isOverview = section === "overview";
  const isAlerts = section === "alerts";
  overviewView.hidden = !isOverview;
  alertsView.hidden = !isAlerts;
  analysisView.hidden = isOverview || isAlerts;
  overviewView.classList.toggle("is-active", isOverview);
  alertsView.classList.toggle("is-active", isAlerts);
  analysisView.classList.toggle("is-active", !isOverview && !isAlerts);
  renderMetrics();
  if (isOverview) renderOverview();
  if (!isOverview && !isAlerts) renderSection(section);
}

function syncInvestigationVisibility() {
  alertDetailPanels.forEach((panel) => {
    panel.hidden = !isInvestigationOpen;
  });
  const needsAlertSelection = currentSection === "alerts" && !isInvestigationOpen;
  copyReportButton.disabled = needsAlertSelection;
  demoAnalyzeButton.disabled = needsAlertSelection || isAnalyzing;
  demoAnalyzeButton.textContent = isAnalyzing ? "Analyzing…" : "Analyze Alert";
  copyReportButton.title = needsAlertSelection ? "Select an alert to copy its report" : "Copy the selected alert report";
  demoAnalyzeButton.title = needsAlertSelection ? "Select an alert to analyze it" : "Analyze the selected alert";
}

function renderAlertTable() {
  tableBody.innerHTML = "";
  const visibleAlerts = filteredAlerts();
  if (!visibleAlerts.length) {
    const message = alerts.length
      ? "No alerts match the current search."
      : `No alerts in ${profileLabels[currentProfile] || currentProfile}. Use another queue scope to inspect the rest of the Wazuh telemetry.`;
    tableBody.innerHTML = `<tr class="empty-table-row"><td colspan="8">${escapeHtml(message)}</td></tr>`;
    return;
  }
  visibleAlerts.forEach((alert) => {
    const triageStatus = alert.triage?.status || "review";
    const severity = severityFor(alert);
    const row = document.createElement("tr");
    row.className = isInvestigationOpen && alert.id === selectedAlert.id ? "is-selected" : "";
    row.tabIndex = 0;
    row.innerHTML = `
      <td class="alert-time-cell">${escapeHtml(compactAlertTime(alert))}</td>
      <td><span class="triage-pill ${escapeHtml(triageStatus)}">${escapeHtml(triageStatus)}</span></td>
      <td><span class="alert-severity-pill ${severity.key}"><span aria-hidden="true"></span>${severity.label} · ${escapeHtml(alert.rule?.level ?? "0")}</span></td>
      <td class="alert-rule-cell"><strong>${escapeHtml(alert.rule?.description || "No description")}</strong><small>${escapeHtml(alert.triage?.reason || alert.event?.channel || "Wazuh alert")}</small></td>
      <td class="mono-cell">${escapeHtml(alert.rule?.id || "-")}</td>
      <td>${escapeHtml(endpoint(alert))}</td>
      <td>${escapeHtml(alert.process?.user || "-")}</td>
      <td class="mono-cell">${escapeHtml(alert.rule?.mitreId || "Unmapped")}</td>
    `;
    row.addEventListener("click", () => selectAlert(alert));
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") selectAlert(alert);
    });
    tableBody.appendChild(row);
  });
}

function topCounts(items, valueFor, limit = 4) {
  const counts = new Map();
  items.forEach((item) => {
    const value = valueFor(item);
    if (!value) return;
    counts.set(value, (counts.get(value) || 0) + 1);
  });
  return [...counts.entries()]
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .slice(0, limit);
}

function renderInsightList(container, entries, emptyLabel) {
  if (!container) return;
  if (!entries.length) {
    container.innerHTML = `<p class="insight-empty">${escapeHtml(emptyLabel)}</p>`;
    return;
  }
  const maximum = entries[0][1] || 1;
  container.innerHTML = entries
    .map(([label, count]) => {
      const width = Math.max(8, Math.round((count / maximum) * 100));
      return `
        <div class="insight-row">
          <div class="insight-row-copy">
            <span title="${escapeHtml(label)}">${escapeHtml(label)}</span>
            <strong>${count}</strong>
          </div>
          <span class="insight-bar" style="--bar-size: ${width}%" aria-hidden="true"></span>
        </div>
      `;
    })
    .join("");
}

function renderAlertInsights() {
  if (alertTotalCount) {
    alertTotalCount.textContent = `${alerts.length} ${alerts.length === 1 ? "alert" : "alerts"}`;
  }
  renderInsightList(
    topRulesList,
    topCounts(alerts, (alert) => alert.rule?.description || "Unlabelled rule"),
    "No rule activity in this queue."
  );
  renderInsightList(
    topEndpointsList,
    topCounts(alerts, (alert) => endpoint(alert) || "Unknown endpoint"),
    "No endpoint activity in this queue."
  );
}

function renderMetrics() {
  quickMetrics.hidden = currentSection === "overview" || currentSection === "alerts";
  workspaceEyebrow.textContent = currentSection === "overview"
    ? "Security operations"
    : currentSection === "alerts"
      ? "Security / Alerts"
      : "Investigation workspace";
  caseTitle.textContent = currentSection === "overview"
    ? "SOC Lab Overview"
    : currentSection === "alerts"
      ? "Security Alerts"
      : selectedAlert.rule?.description || "Wazuh alert investigation";
  openAlertsMetric.textContent = alertSummary.candidates ?? alerts.length;
  reviewAlertsMetric.textContent = alertSummary.review ?? "-";
  rawAlertsMetric.textContent = alertSummary.raw ?? "-";
  suppressedAlertsMetric.textContent = alertSummary.suppressed ?? "-";
  severityBadge.textContent = `Level ${selectedAlert.rule?.level ?? "-"}`;
  queueModePill.textContent = `${profileLabels[currentProfile] || "Alerts"} · ${alerts.length}`;
  const severity = alertSummary.severity || {};
  alertCriticalCount.textContent = severity.critical ?? 0;
  alertHighCount.textContent = severity.high ?? 0;
  alertMediumCount.textContent = severity.medium ?? 0;
  alertLowCount.textContent = severity.low ?? 0;
  renderAlertInsights();
  queueTabs.forEach((button) => {
    button.classList.toggle("is-active", button.dataset.profile === currentProfile);
  });
  syncInvestigationVisibility();
}

function renderOverview() {
  if (!overviewView) return;
  const severity = alertSummary.severity || {};
  const agents = alertSummary.agents || {};
  const inferredActiveAgents = new Set(alerts.map((alert) => alert.agent?.name).filter(Boolean)).size;
  const activeCount = agents.active ?? inferredActiveAgents;
  const disconnectedCount = agents.disconnected ?? 0;

  overviewActiveAgents.textContent = activeCount;
  overviewDisconnectedAgents.textContent = disconnectedCount;
  overviewCriticalAlerts.textContent = severity.critical ?? 0;
  overviewHighAlerts.textContent = severity.high ?? 0;
  overviewMediumAlerts.textContent = severity.medium ?? 0;
  overviewLowAlerts.textContent = severity.low ?? 0;

  const recentCandidates = alerts
    .filter((alert) => (alert.triage?.status || "") === "candidate")
    .slice(0, 5);
  const recent = recentCandidates.length ? recentCandidates : alerts.slice(0, 5);

  if (!recent.length) {
    overviewRecentList.innerHTML = `
      <div class="empty-overview-state">
        <strong>No recent candidates</strong>
        <span>Generate a lab event or open the Review queue to inspect lower-priority alerts.</span>
      </div>
    `;
    return;
  }

  overviewRecentList.innerHTML = recent
    .map((alert) => `
      <button class="recent-alert" type="button" data-alert-id="${escapeHtml(alert.id)}">
        <span>
          <strong>${escapeHtml(alert.rule?.description || "Wazuh alert")}</strong>
          <small>${escapeHtml(alertTime(alert))} · ${escapeHtml(endpoint(alert))}</small>
        </span>
        <em>Level ${escapeHtml(alert.rule?.level ?? "-")}</em>
      </button>
    `)
    .join("");

  overviewRecentList.querySelectorAll(".recent-alert").forEach((button) => {
    button.addEventListener("click", () => {
      const alert = alerts.find((item) => item.id === button.dataset.alertId);
      if (alert) selectAlert(alert);
      setSection("alerts");
    });
  });
}

function renderDetails() {
  const rows = [
    ["Triage", `${selectedAlert.triage?.status || "review"} - ${selectedAlert.triage?.reason || "No reason"}`],
    ["Policy rule", selectedAlert.triage?.policyRule
      ? `${selectedAlert.triage.policyRule} - ${selectedAlert.triage.policyTitle || "Matched policy"}`
      : "Default triage policy"],
    ["Policy matches", selectedAlert.triage?.matches?.length
      ? selectedAlert.triage.matches.map((match) => match.id).join(", ")
      : "None"],
    ["Rule ID", selectedAlert.rule?.id],
    ["Description", selectedAlert.rule?.description],
    ["Agent", `${endpoint(selectedAlert)} (${selectedAlert.agent?.ip || "no IP"})`],
    ["User", selectedAlert.process?.user || "Unknown"],
    ["Source", selectedAlert.event?.channel],
    ["Event ID", selectedAlert.event?.eventId],
    ["Image", selectedAlert.process?.image],
    ["Parent", selectedAlert.process?.parentImage || "Unavailable"],
    ["Command line", commandLine(selectedAlert)],
    ["MITRE", mitreLabel(selectedAlert)],
    ["Context loaded", surroundingEvents.length ? `${surroundingEvents.length} events` : "Not loaded"],
  ];

  details.innerHTML = rows
    .map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value || "Unavailable")}</dd>`)
    .join("");
}

function renderRawEvent() {
  rawEventOutput.textContent = JSON.stringify(selectedAlert, null, 2);
}

function addMessage(kind, text, meta = "") {
  const message = document.createElement("div");
  message.className = `message ${kind}`;
  const label = kind.startsWith("ai") ? "AI Analyst" : "You";
  // Alert text can contain attacker-controlled command lines, so everything is
  // escaped before any markdown formatting is applied.
  const body = kind.startsWith("ai") ? renderMarkdown(text) : `<p>${inlineMarkdown(text)}</p>`;
  const footer = meta ? `<span class="message-meta">${escapeHtml(meta)}</span>` : "";
  message.innerHTML = `<strong>${escapeHtml(label)}</strong>${body}${footer}`;
  chatLog.appendChild(message);
  chatLog.scrollTop = chatLog.scrollHeight;
  return message;
}

function analysisMeta(payload) {
  const usage = payload.usage || {};
  const tokens = `${usage.inputTokens || 0} in / ${usage.outputTokens || 0} out`;

  if (payload.mode === "claude") {
    const cost = Number(usage.costUsd || 0).toFixed(4);
    return `${payload.model} · ${tokens} · $${cost}`;
  }
  if (payload.mode === "ollama") {
    const seconds = usage.seconds ? ` · ${usage.seconds}s` : "";
    return `${payload.model} (local) · ${tokens}${seconds} · free`;
  }
  return `Template mode — ${payload.reason || "no model backend reachable"}`;
}

async function requestAnalysis(task, question = "") {
  if (isAnalyzing) return;
  isAnalyzing = true;
  syncInvestigationVisibility();
  const pending = addMessage("ai pending", "Analyzing the evidence…");

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        task,
        question,
        alert: selectedAlert,
        context: surroundingEvents,
      }),
    });
    if (!response.ok) throw new Error(`Analyze request failed: ${response.status}`);
    const payload = await response.json();
    pending.remove();
    addMessage("ai", payload.text, analysisMeta(payload));
    setArtifact(payload.title || task, payload.text);
  } catch {
    // No backend (static demo build) or the request failed: use the local
    // evidence templates so the panel still renders.
    pending.remove();
    const text = answerForPrompt(question || task);
    addMessage("ai", text, "Offline template mode — no analysis backend reachable");
    setArtifact("Generated", text);
  } finally {
    isAnalyzing = false;
    syncInvestigationVisibility();
  }
}

function answerForPrompt(prompt) {
  const normalized = prompt.toLowerCase();
  const artifacts = artifactTemplates(selectedAlert);

  if (normalized.includes("timeline")) return artifacts.timeline;
  if (normalized.includes("mitre") || normalized.includes("attack")) return artifacts.mitre;
  if (normalized.includes("response") || normalized.includes("contain")) return artifacts.response;
  if (normalized.includes("detect") || normalized.includes("sigma") || normalized.includes("rule")) return artifacts.detection;
  if (normalized.includes("command") || normalized.includes("evidence")) {
    return `Key Evidence

Command line:
${commandLine(selectedAlert)}

Source:
${selectedAlert.event?.channel || "Unknown source"} Event ID ${selectedAlert.event?.eventId || "unknown"}

Wazuh rule:
${selectedAlert.rule?.id || "unknown"} - ${selectedAlert.rule?.description || "No description"}`;
  }

  return artifacts.summary;
}

function setArtifact(name, content) {
  artifactStatus.textContent = name;
  artifactOutput.textContent = content;
}

function selectAlert(alert) {
  selectedAlert = alert;
  isInvestigationOpen = true;
  surroundingEvents = [];
  renderMetrics();
  renderOverview();
  renderAlertTable();
  renderDetails();
  renderRawEvent();
  setArtifact("Summary", artifactTemplates(selectedAlert).summary);
  renderSection();
  loadContext(alert);
}

async function loadSnapshot() {
  if (snapshot) return snapshot;
  try {
    const response = await fetch("./sample-data/snapshot.json");
    if (!response.ok) throw new Error("No snapshot available");
    snapshot = await response.json();
    return snapshot;
  } catch {
    return null;
  }
}

async function loadContext(alert) {
  if (isSnapshotMode) {
    surroundingEvents = snapshot?.context?.[alert.id] || [];
    renderDetails();
    renderSection();
    return;
  }
  if (!alert.id || !alert.index || alert.index === "demo" || alert.index === "empty") return;
  try {
    const response = await fetch(`/api/alerts/${encodeURIComponent(alert.id)}/context?index=${encodeURIComponent(alert.index)}`);
    const payload = await response.json();
    surroundingEvents = payload.events || [];
    renderDetails();
    renderSection();
  } catch {
    surroundingEvents = [];
    renderSection();
  }
}

async function loadAlerts() {
  isInvestigationOpen = false;
  dataModeLabel.textContent = "Connecting";
  dataModeText.textContent = "Querying Wazuh";
  try {
    const response = await fetch(`/api/alerts?minutes=${alertMinutes}&min_level=4&size=50&profile=${encodeURIComponent(currentProfile)}`);
    if (!response.ok) throw new Error("Wazuh API unavailable");
    const payload = await response.json();
    isSnapshotMode = false;
    alertSummary = payload.summary || {};
    alerts = payload.alerts || [];
    selectedAlert = alerts[0] || emptyAlert;
    dataModeLabel.textContent = payload.mode === "live" ? "Live Wazuh" : "Demo mode";
    dataModeText.textContent = payload.mode === "live"
      ? `${alertSummary.candidates || 0} candidates, ${alertSummary.review || 0} review, ${alertSummary.raw || 0} raw`
      : "Using sample alert";
    queueModePill.textContent = payload.mode === "live" ? profileLabels[currentProfile] : "Demo fallback";
  } catch {
    // No live indexer. Serve the frozen export of real lab alerts if one was
    // built (this is what the hosted demo runs on), otherwise the single
    // bundled sample alert.
    const frozen = await loadSnapshot();
    if (frozen) {
      isSnapshotMode = true;
      alerts = frozen.queues?.[currentProfile] || [];
      alertSummary = frozen.summary?.[currentProfile] || {};
      selectedAlert = alerts[0] || emptyAlert;
      const captured = frozen.generatedAt
        ? new Date(frozen.generatedAt).toLocaleDateString(undefined, {
            year: "numeric",
            month: "short",
            day: "numeric",
          })
        : "unknown date";
      dataModeLabel.textContent = "Snapshot";
      dataModeText.textContent = `Real alerts frozen ${captured}`;
      queueModePill.textContent = profileLabels[currentProfile] || "Alerts";
    } else {
      isSnapshotMode = false;
      alerts = [demoAlert];
      selectedAlert = demoAlert;
      alertSummary = {
        raw: 1,
        candidates: 1,
        review: 0,
        suppressed: 0,
        severity: { critical: 0, high: 0, medium: 0, low: 1 },
        agents: { active: 1, disconnected: 0 },
      };
      dataModeLabel.textContent = "Demo mode";
      dataModeText.textContent = "Wazuh unavailable";
      queueModePill.textContent = "Demo fallback";
    }
  }
  surroundingEvents = [];
  renderMetrics();
  renderOverview();
  renderAlertTable();
  renderDetails();
  renderRawEvent();
  setArtifact("Summary", artifactTemplates(selectedAlert).summary);
  renderSection();
  loadContext(selectedAlert);
}

queueTabs.forEach((button) => {
  button.addEventListener("click", () => {
    currentProfile = button.dataset.profile;
    loadAlerts();
  });
});

document.querySelectorAll("[data-prompt]").forEach((button) => {
  button.addEventListener("click", () => {
    addMessage("user", button.textContent);
    requestAnalysis(button.dataset.prompt);
  });
});

navItems.forEach((button) => {
  button.addEventListener("click", () => {
    setSection(button.dataset.section);
  });
});

document.querySelectorAll("[data-overview-section]").forEach((button) => {
  button.addEventListener("click", () => {
    setSection(button.dataset.overviewSection);
  });
});

document.querySelectorAll("[data-overview-profile]").forEach((button) => {
  button.addEventListener("click", () => {
    currentProfile = button.dataset.overviewProfile;
    setSection("alerts");
    loadAlerts();
  });
});

chatForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const text = chatInput.value.trim();
  if (!text) return;
  addMessage("user", text);
  chatInput.value = "";
  requestAnalysis("chat", text);
});

demoAnalyzeButton.addEventListener("click", () => {
  if (!isInvestigationOpen) return;
  addMessage("user", "Analyze this alert");
  requestAnalysis("summary");
});

copyReportButton.addEventListener("click", async () => {
  const reportMarkdown = reportFor(selectedAlert);
  try {
    await navigator.clipboard.writeText(reportMarkdown);
    setArtifact("Copied", reportMarkdown);
  } catch {
    setArtifact("Report", reportMarkdown);
  }
});

document.querySelector("#refreshAlertsButton").addEventListener("click", loadAlerts);

alertSearchInput.addEventListener("input", (event) => {
  alertSearchTerm = event.target.value;
  renderAlertTable();
});

alertTimeRange.addEventListener("change", (event) => {
  alertMinutes = Number(event.target.value) || 1440;
  loadAlerts();
});

clearAlertFilters.addEventListener("click", () => {
  alertSearchTerm = "";
  alertMinutes = 1440;
  alertSearchInput.value = "";
  alertTimeRange.value = "1440";
  loadAlerts();
});

closeAlertInvestigation.addEventListener("click", () => {
  isInvestigationOpen = false;
  renderMetrics();
  renderAlertTable();
});

async function loadHealth() {
  try {
    const response = await fetch("/api/health");
    const payload = await response.json();
    aiStatus = payload.ai || { enabled: false, reason: "Backend did not report AI status" };
  } catch {
    aiStatus = { enabled: false, reason: "No analysis backend reachable" };
  }
  renderAiStatus();
}

const providerLabels = {
  claude: "Claude API",
  ollama: "Local model",
  template: "Template mode",
};

function renderAiStatus() {
  const provider = aiStatus.provider || (aiStatus.enabled ? "claude" : "template");
  const label = providerLabels[provider] || provider;
  if (aiStatus.enabled) {
    aiModeText.textContent = `AI: ${aiStatus.model}`;
    aiPanelPill.textContent = `${label} · evidence-bound`;
    brandMode.textContent = provider === "ollama" ? "Local AI" : "Investigation console";
  } else {
    aiModeText.textContent = "AI: template mode";
    aiPanelPill.textContent = "Template mode";
    brandMode.textContent = "Template mode";
  }
  aiModeText.title = aiStatus.reason || `${label}${aiStatus.model ? ` (${aiStatus.model})` : ""}`;
}

addMessage(
  "ai",
  "Select a Wazuh alert, then ask for a **summary**, **timeline**, **MITRE** mapping, **response** plan, or **detection** logic.",
);
loadHealth();
loadAlerts();
