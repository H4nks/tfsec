package formatters

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"
	"github.com/aquasecurity/tfsec/version"
	gitlab_report "gitlab.com/gitlab-org/security-products/analyzers/report/v3"
)

func FormatGLSAST(w io.Writer, results []result.Result, _ string, options ...FormatterOption) error {
	r := gitlab_report.NewReport()

	scanner := gitlab_report.ScannerDetails{
		ID:   "aquasecurity-tfsec",
		Name: "Tfsec",
		URL:  "https://tfsec.dev/",
		Vendor: gitlab_report.Vendor{
			Name: "AquaSecurity",
		},
		Version: version.Version,
	}

	r.Scan = gitlab_report.Scan{
		Scanner: scanner,
		Type:    gitlab_report.CategorySast,
	}

	r.Version = gitlab_report.CurrentVersion()

	for _, result := range results {
		r.Vulnerabilities = append(r.Vulnerabilities,
			gitlab_report.Vulnerability{
				Category:    gitlab_report.CategorySast,
				Description: result.Description,
				Name:        result.RuleID,
				Message:     fmt.Sprintf("%s. %s", result.Impact, result.RuleSummary),
				Links:       gitlab_report.NewLinks(result.Links...),
				Location: gitlab_report.Location{
					File:      result.Location.Filename,
					LineStart: result.Location.StartLine,
					LineEnd:   result.Location.EndLine,
				},
				Identifiers: []gitlab_report.Identifier{
					{
						Type:  gitlab_report.IdentifierType("tfsec"),
						Name:  result.RuleID,
						Value: result.LegacyRuleID,
					},
				},
				Solution: result.Resolution,
				Severity: glSeverityLevel(&result),
				Scanner: gitlab_report.Scanner{
					ID:   scanner.ID,
					Name: scanner.Name,
				},
				RawSourceCodeExtract: extractRawCode(&result),
			},
		)
	}
	r.Sort()
	return json.NewEncoder(w).Encode(r)
}

func extractRawCode(result *result.Result) string {
	data, err := ioutil.ReadFile(result.Range().Filename)
	if err != nil {
		return ""
	}

	lines := append([]string{""}, strings.Split(string(data), "\n")...)

	start := result.Range().StartLine - 3
	if start <= 0 {
		start = 1
	}
	end := result.Range().EndLine + 3
	if end >= len(lines) {
		end = len(lines) - 1
	}

	return strings.Join(lines[start:end], "\n")
}

func glSeverityLevel(result *result.Result) gitlab_report.SeverityLevel {
	if result.Passed() {
		return gitlab_report.SeverityLevelInfo
	}

	switch result.Severity {
	case severity.Low:
		return gitlab_report.SeverityLevelLow
	case severity.Medium:
		return gitlab_report.SeverityLevelMedium
	case severity.High:
		return gitlab_report.SeverityLevelHigh
	case severity.Critical:
		return gitlab_report.SeverityLevelCritical
	}

	return gitlab_report.SeverityLevelUnknown
}
