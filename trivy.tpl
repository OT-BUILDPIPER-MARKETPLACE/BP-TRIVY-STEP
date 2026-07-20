<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Trivy Security Report</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',Arial,sans-serif;background:#f0f2f5;color:#1a1a2e;font-size:14px;line-height:1.5}

  .header{background:linear-gradient(135deg,#1a1a2e 0%,#16213e 60%,#0f3460 100%);color:#fff;padding:32px 40px;border-bottom:4px solid #e94560}
  .header h1{font-size:26px;font-weight:700;letter-spacing:0.5px;margin-bottom:6px}
  .header .meta{font-size:12px;opacity:0.65;font-family:monospace}

  .summary{display:flex;flex-wrap:wrap;gap:14px;padding:22px 40px;background:#fff;border-bottom:1px solid #e2e8f0}
  .summary-card{flex:1;min-width:120px;background:#f8fafc;border-radius:8px;padding:12px 16px;border-left:4px solid;text-align:center}
  .summary-card .num{font-size:26px;font-weight:800;line-height:1}
  .summary-card .label{font-size:10px;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;margin-top:4px}
  .sc-critical{border-color:#dc2626}.sc-critical .num{color:#dc2626}
  .sc-high{border-color:#ea580c}.sc-high .num{color:#ea580c}
  .sc-medium{border-color:#ca8a04}.sc-medium .num{color:#ca8a04}
  .sc-low{border-color:#16a34a}.sc-low .num{color:#16a34a}
  .sc-unknown{border-color:#94a3b8}.sc-unknown .num{color:#94a3b8}
  .sc-misconfig{border-color:#7c3aed}.sc-misconfig .num{color:#7c3aed}
  .sc-secret{border-color:#db2777}.sc-secret .num{color:#db2777}
  .sc-license{border-color:#0284c7}.sc-license .num{color:#0284c7}
  .sc-total{border-color:#1e293b;background:#f1f5f9}.sc-total .num{color:#1e293b}

  .content{max-width:1400px;margin:28px auto;padding:0 32px}

  .target-block{background:#fff;border-radius:10px;box-shadow:0 1px 6px rgba(0,0,0,0.07);margin-bottom:28px;overflow:hidden;border:1px solid #e2e8f0}
  .target-header{display:flex;align-items:center;gap:12px;padding:14px 20px;background:#f8fafc;border-bottom:1px solid #e2e8f0;flex-wrap:wrap}
  .target-name{font-weight:700;font-size:14px;color:#1e293b;font-family:monospace;word-break:break-all}
  .target-type{font-size:11px;background:#e2e8f0;color:#475569;padding:2px 8px;border-radius:999px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;white-space:nowrap}
  .target-class{font-size:11px;background:#dbeafe;color:#1e40af;padding:2px 8px;border-radius:999px;font-weight:600;white-space:nowrap}

  .section{padding:18px 20px}
  .section-title{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:14px;padding-bottom:8px;border-bottom:2px solid}
  .st-vuln{color:#dc2626;border-color:#fecaca}
  .st-misconf{color:#7c3aed;border-color:#ede9fe}
  .st-secret{color:#db2777;border-color:#fce7f3}
  .st-license{color:#0284c7;border-color:#e0f2fe}

  .scan-table{width:100%;border-collapse:collapse;font-size:13px}
  .scan-table th{background:#f1f5f9;color:#475569;padding:9px 12px;text-align:left;font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;border-bottom:2px solid #e2e8f0;white-space:nowrap}
  .scan-table td{padding:9px 12px;border-bottom:1px solid #f1f5f9;vertical-align:top}
  .scan-table tr:last-child td{border-bottom:none}
  .scan-table tr:hover td{background:#fafbfd}

  .sev{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:0.5px;white-space:nowrap}
  .sev-CRITICAL{background:#fee2e2;color:#991b1b;border:1px solid #fca5a5}
  .sev-HIGH{background:#ffedd5;color:#9a3412;border:1px solid #fdba74}
  .sev-MEDIUM{background:#fef9c3;color:#854d0e;border:1px solid #fde047}
  .sev-LOW{background:#dcfce7;color:#166534;border:1px solid #86efac}
  .sev-UNKNOWN{background:#f1f5f9;color:#475569;border:1px solid #cbd5e1}

  .status-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px}
  .status-fixed{background:#dcfce7;color:#166534}
  .status-affected{background:#fee2e2;color:#991b1b}
  .status-will_not_fix{background:#fef3c7;color:#92400e}
  .status-under_investigation{background:#e0f2fe;color:#0c4a6e}
  .status-end_of_life{background:#f3e8ff;color:#6b21a8}

  .misconf-fail{background:#fee2e2;color:#991b1b;display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700}
  .misconf-pass{background:#dcfce7;color:#166534;display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700}
  .misconf-exception{background:#fef3c7;color:#92400e;display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700}

  .clean-row{padding:12px 20px;display:flex;align-items:center;gap:8px;font-size:13px;color:#16a34a;background:#f0fdf4;border-top:1px solid #dcfce7}
  .clean-row span{font-weight:600}

  td.pkg{font-family:monospace;font-weight:700;color:#1e293b;font-size:12px}
  td.mono{font-family:monospace;font-size:12px;color:#475569}
  td.fixver{font-family:monospace;font-size:12px;color:#16a34a;font-weight:600}
  td.fixver-na{font-family:monospace;font-size:12px;color:#94a3b8}
  td.title-col{font-size:12px;color:#374151;max-width:260px}
  td.desc-col{font-size:12px;color:#64748b;max-width:300px;line-height:1.5}
  td.match-col{font-family:monospace;font-size:11px;color:#7c3aed;background:#f5f3ff;padding:4px 8px;border-radius:4px;max-width:220px;word-break:break-all}
  td.path-col{font-family:monospace;font-size:11px;color:#475569;max-width:200px;word-break:break-all}

  .cwe-tag{display:inline-block;background:#ede9fe;color:#5b21b6;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;margin-right:3px;font-family:monospace}
  .ref-link{font-size:11px;color:#0284c7;text-decoration:none;display:block;margin-bottom:2px;font-family:monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:240px}
  .ref-link:hover{text-decoration:underline}

  .lic-restricted{background:#fee2e2;color:#991b1b;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700}
  .lic-notice{background:#dcfce7;color:#166534;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700}
  .lic-permissive{background:#f0fdf4;color:#166534;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700}
  .lic-unencumbered{background:#f0fdf4;color:#166534;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700}
  .lic-reciprocal{background:#fef9c3;color:#854d0e;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700}
  .lic-unknown{background:#f1f5f9;color:#475569;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700}
  .lic-forbidden{background:#fee2e2;color:#991b1b;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700}
  .lic-conditional{background:#fef3c7;color:#92400e;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700}

  .divider{border:none;border-top:1px solid #f1f5f9;margin:0}
  .footer{text-align:center;padding:28px;color:#94a3b8;font-size:12px;font-family:monospace;border-top:1px solid #e2e8f0;margin-top:12px;background:#fff}
</style>
</head>
<body>

<div class="header">
  <h1>&#127697; Trivy Security Report</h1>
  <div class="meta">Generated: {{ now }} &nbsp;|&nbsp; Scanner: Aqua Security Trivy</div>
</div>

{{- $totalCritical := 0 -}}
{{- $totalHigh := 0 -}}
{{- $totalMedium := 0 -}}
{{- $totalLow := 0 -}}
{{- $totalUnknown := 0 -}}
{{- $totalMisconf := 0 -}}
{{- $totalSecret := 0 -}}
{{- $totalLicense := 0 -}}
{{- range . -}}
  {{- range .Vulnerabilities -}}
    {{- if eq .Severity "CRITICAL" }}{{- $totalCritical = add $totalCritical 1 -}}{{- end -}}
    {{- if eq .Severity "HIGH" }}{{- $totalHigh = add $totalHigh 1 -}}{{- end -}}
    {{- if eq .Severity "MEDIUM" }}{{- $totalMedium = add $totalMedium 1 -}}{{- end -}}
    {{- if eq .Severity "LOW" }}{{- $totalLow = add $totalLow 1 -}}{{- end -}}
    {{- if eq .Severity "UNKNOWN" }}{{- $totalUnknown = add $totalUnknown 1 -}}{{- end -}}
  {{- end -}}
  {{- range .Misconfigurations -}}
    {{- if eq (toString .Status) "FAIL" }}{{- $totalMisconf = add $totalMisconf 1 -}}{{- end -}}
  {{- end -}}
  {{- $totalSecret = add $totalSecret (len .Secrets) -}}
  {{- $totalLicense = add $totalLicense (len .Licenses) -}}
{{- end -}}
{{- $grandTotal := add $totalCritical $totalHigh $totalMedium $totalLow $totalUnknown $totalMisconf $totalSecret -}}

<div class="summary">
  <div class="summary-card sc-critical"><div class="num">{{ $totalCritical }}</div><div class="label">Critical CVEs</div></div>
  <div class="summary-card sc-high"><div class="num">{{ $totalHigh }}</div><div class="label">High CVEs</div></div>
  <div class="summary-card sc-medium"><div class="num">{{ $totalMedium }}</div><div class="label">Medium CVEs</div></div>
  <div class="summary-card sc-low"><div class="num">{{ $totalLow }}</div><div class="label">Low CVEs</div></div>
  <div class="summary-card sc-unknown"><div class="num">{{ $totalUnknown }}</div><div class="label">Unknown CVEs</div></div>
  <div class="summary-card sc-misconfig"><div class="num">{{ $totalMisconf }}</div><div class="label">Misconfigs</div></div>
  <div class="summary-card sc-secret"><div class="num">{{ $totalSecret }}</div><div class="label">Secrets</div></div>
  <div class="summary-card sc-license"><div class="num">{{ $totalLicense }}</div><div class="label">Licenses</div></div>
  <div class="summary-card sc-total"><div class="num">{{ $grandTotal }}</div><div class="label">Total Issues</div></div>
</div>

<div class="content">
{{ range . }}
<div class="target-block">

  <div class="target-header">
    <div class="target-name">{{ .Target }}</div>
    {{ if .Type }}<span class="target-type">{{ .Type }}</span>{{ end }}
    {{ if .Class }}<span class="target-class">{{ .Class }}</span>{{ end }}
  </div>

  {{- if .Vulnerabilities }}
  <div class="section">
    <div class="section-title st-vuln">Vulnerabilities ({{ len .Vulnerabilities }})</div>
    <table class="scan-table">
      <thead>
        <tr>
          <th>Package</th>
          <th>CVE / ID</th>
          <th>Severity</th>
          <th>Status</th>
          <th>Installed Version</th>
          <th>Fixed Version</th>
          <th>Title</th>
          <th>CWEs</th>
        </tr>
      </thead>
      <tbody>
        {{- range .Vulnerabilities }}
        <tr>
          <td class="pkg">{{ .PkgName }}{{ if .PkgPath }}<br><span style="font-size:10px;color:#94a3b8;font-weight:400">{{ .PkgPath }}</span>{{ end }}</td>
          <td class="mono">{{ if .PrimaryURL }}<a href="{{ .PrimaryURL }}" target="_blank" style="color:#0284c7;text-decoration:none">{{ .VulnerabilityID }}</a>{{ else }}{{ .VulnerabilityID }}{{ end }}</td>
          <td><span class="sev sev-{{ .Severity }}">{{ .Severity }}</span></td>
          <td>{{ if .Status }}<span class="status-badge status-{{ .Status }}">{{ .Status }}</span>{{ end }}</td>
          <td class="mono">{{ .InstalledVersion }}</td>
          <td class="{{ if .FixedVersion }}fixver{{ else }}fixver-na{{ end }}">{{ if .FixedVersion }}{{ .FixedVersion }}{{ else }}&ndash;{{ end }}</td>
          <td class="title-col">{{ .Title }}</td>
          <td>{{ range .CweIDs }}<span class="cwe-tag">{{ . }}</span>{{ end }}</td>
        </tr>
        {{- end }}
      </tbody>
    </table>
  </div>
  <hr class="divider">
  {{- else }}
  <div class="clean-row">&#10003; <span>No Vulnerabilities Found</span></div>
  {{- end }}

  {{- if .Misconfigurations }}
  <div class="section">
    <div class="section-title st-misconf">Misconfigurations ({{ len .Misconfigurations }})</div>
    {{- if .MisconfSummary }}
    <div style="font-size:12px;color:#64748b;margin-bottom:12px;padding:8px 12px;background:#f8fafc;border-radius:6px;border:1px solid #e2e8f0">
      Summary &rarr;
      <span style="color:#dc2626;font-weight:700">Failures: {{ .MisconfSummary.Failures }}</span> &nbsp;|&nbsp;
      <span style="color:#16a34a;font-weight:700">Successes: {{ .MisconfSummary.Successes }}</span>
    </div>
    {{- end }}
    <table class="scan-table">
      <thead>
        <tr>
          <th>ID</th>
          <th>AVD ID</th>
          <th>Type</th>
          <th>Severity</th>
          <th>Status</th>
          <th>Title</th>
          <th>Message</th>
          <th>Resolution</th>
        </tr>
      </thead>
      <tbody>
        {{- range .Misconfigurations }}
        <tr>
          <td class="mono" style="font-size:11px">{{ .ID }}</td>
          <td class="mono" style="font-size:11px">{{ if .PrimaryURL }}<a href="{{ .PrimaryURL }}" target="_blank" style="color:#0284c7;text-decoration:none">{{ .AVDID }}</a>{{ else }}{{ .AVDID }}{{ end }}</td>
          <td style="font-size:11px;color:#475569">{{ .Type }}</td>
          <td><span class="sev sev-{{ .Severity }}">{{ .Severity }}</span></td>
          <td>{{ if eq (toString .Status) "FAIL" }}<span class="misconf-fail">FAIL</span>{{ else if eq (toString .Status) "PASS" }}<span class="misconf-pass">PASS</span>{{ else }}<span class="misconf-exception">{{ .Status }}</span>{{ end }}</td>
          <td class="title-col">{{ .Title }}</td>
          <td class="desc-col">{{ .Message }}</td>
          <td class="desc-col">{{ .Resolution }}</td>
        </tr>
        {{- end }}
      </tbody>
    </table>
  </div>
  <hr class="divider">
  {{- else }}
  <div class="clean-row">&#10003; <span>No Misconfigurations Found</span></div>
  {{- end }}

  {{- if .Secrets }}
  <div class="section">
    <div class="section-title st-secret">Secrets ({{ len .Secrets }})</div>
    <table class="scan-table">
      <thead>
        <tr>
          <th>Rule ID</th>
          <th>Category</th>
          <th>Severity</th>
          <th>Title</th>
          <th>Line Range</th>
          <th>Matched Content</th>
        </tr>
      </thead>
      <tbody>
        {{- range .Secrets }}
        <tr>
          <td class="mono" style="font-size:11px">{{ .RuleID }}</td>
          <td style="font-size:11px;color:#475569">{{ .Category }}</td>
          <td><span class="sev sev-{{ .Severity }}">{{ .Severity }}</span></td>
          <td class="title-col">{{ .Title }}</td>
          <td class="mono" style="font-size:11px;white-space:nowrap">{{ if .StartLine }}L{{ .StartLine }}{{ if .EndLine }} &ndash; L{{ .EndLine }}{{ end }}{{ end }}</td>
          <td class="match-col">{{ .Match }}</td>
        </tr>
        {{- end }}
      </tbody>
    </table>
  </div>
  <hr class="divider">
  {{- else }}
  <div class="clean-row">&#10003; <span>No Secrets Found</span></div>
  {{- end }}

  {{- if .Licenses }}
  <div class="section">
    <div class="section-title st-license">License Findings ({{ len .Licenses }})</div>
    <table class="scan-table">
      <thead>
        <tr>
          <th>Package</th>
          <th>License</th>
          <th>Severity</th>
          <th>Category</th>
          <th>File Path</th>
          <th>Confidence</th>
          <th>Reference</th>
        </tr>
      </thead>
      <tbody>
        {{- range .Licenses }}
        <tr>
          <td class="pkg">{{ .PkgName }}</td>
          <td style="font-weight:600;font-size:12px">{{ .Name }}</td>
          <td><span class="sev sev-{{ .Severity }}">{{ .Severity }}</span></td>
          <td><span class="lic-{{ lower (toString .Category) }}">{{ .Category }}</span></td>
          <td class="path-col">{{ .FilePath }}</td>
          <td style="font-size:12px;color:#475569;text-align:center">{{ if .Confidence }}{{ printf "%.0f%%" (mulf .Confidence 100) }}{{ else }}&ndash;{{ end }}</td>
          <td>{{ if .Link }}<a href="{{ .Link }}" target="_blank" class="ref-link">reference</a>{{ else }}&ndash;{{ end }}</td>
        </tr>
        {{- end }}
      </tbody>
    </table>
  </div>
  {{- else }}
  <div class="clean-row">&#10003; <span>No License Issues Found</span></div>
  {{- end }}

</div>
{{ end }}
</div>

<div class="footer">
  Generated by Trivy (Aqua Security) &nbsp;|&nbsp; {{ now }}
</div>

</body>
</html>

