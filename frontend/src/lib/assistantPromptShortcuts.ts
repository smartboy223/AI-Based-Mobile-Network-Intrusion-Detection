/**
 * Quick prompts: plain labels + hints for non-experts. {{IP}} uses the Focus IP field.
 */
export type PromptShortcut = {
  id: string;
  /** Short button text */
  label: string;
  /** Shown as tooltip — simple language */
  hint: string;
  template: string;
};

export const ASSISTANT_PROMPT_SHORTCUTS: PromptShortcut[] = [
  {
    id: 'summary',
    label: 'Summarize my traffic',
    hint: 'Plain-language overview of safe vs suspicious rows on the table right now.',
    template:
      'Using only the Evidence JSON, give a concise executive summary: counts of benign vs malicious rows, dominant attack types (if any), and the three highest-risk flows by confidence (cite each row id).',
  },
  {
    id: 'ip-focus',
    label: 'Focus on one IP',
    hint: 'Type an IP below first. Lists every row involving that IP and suggests how to watch for similar traffic.',
    template:
      'Focus strictly on IP {{IP}} in the Evidence. Use ipOccurrencesInFullTable for a one-line count summary, then list each trafficRows row (and note if more rows exist outside the slice). Propose a concrete detection rule (thresholds on volume, protocol, or interface hints) grounded only in Evidence.',
  },
  {
    id: 'detection-draft',
    label: 'Simple alert idea for IP',
    hint: 'Fill in the IP field. Gets a short “if you see this, flag it” style description.',
    template:
      'Draft a short, implementable detection description (pseudocode or bullet conditions) for suspicious activity involving IP {{IP}}, based only on patterns visible in the Evidence for that IP. Include suggested log fields to match on and a severity rationale. If the IP is missing from Evidence, say so.',
  },
  {
    id: 'gtp-n3',
    label: '5G / GTP / core traffic',
    hint: 'Explains rows that look like 5G user plane or core signaling in the current data.',
    template:
      'From the Evidence only, summarize flows that mention GTP-U, N3, UPF, NGAP, NAS-5G, or related 5G fields. Note anomalies or high-confidence alerts and cite row ids.',
  },
  {
    id: 'pcap-next',
    label: 'What to check in Wireshark',
    hint: 'Practical filter ideas based only on IPs and protocols already in your table.',
    template:
      'Given protocols and IPs that actually appear in the Evidence, suggest practical next checks an analyst could run in Wireshark (display filters, follow-TCP/UDP) without claiming packets that are not in Evidence.',
  },
  {
    id: 'false-positive',
    label: 'Could this be a false alarm?',
    hint: 'Looks at “malicious” rows and says if they might be normal noise.',
    template:
      'Review malicious-labeled rows in the Evidence. For each, state whether the label could plausibly be benign noise (and why), staying within facts in the data. Cite row ids.',
  },
];

export function applyIpPlaceholder(template: string, ip: string): string {
  const trimmed = ip.trim();
  const replacement = trimmed || '(type the IP in the box above the buttons)';
  return template.replace(/\{\{IP\}\}/g, replacement);
}
