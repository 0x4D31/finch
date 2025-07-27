package admin

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/0x4D31/finch/internal/rules"
)

type rulePos struct{ start, end int }

func parseBytes(data []byte) (map[string]rulePos, error) {
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(data, "<mem>")
	if diags.HasErrors() {
		return nil, errors.New(diags.Error())
	}
	schema := &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "rule", LabelNames: []string{"name"}}}}
	content, diags := file.Body.Content(schema)
	if diags.HasErrors() {
		return nil, errors.New(diags.Error())
	}
	m := make(map[string]rulePos)
	for _, blk := range content.Blocks {
		if len(blk.Labels) != 1 {
			continue
		}
		start := blk.DefRange.Start.Byte
		end := blk.DefRange.End.Byte
		if sb, ok := blk.Body.(*hclsyntax.Body); ok {
			end = sb.Range().End.Byte
		}
		for start > 0 && data[start-1] != '\n' {
			start--
		}
		for start > 0 && data[start-1] == '\n' {
			start--
		}
		for end < len(data) && data[end] != '\n' {
			end++
		}
		for end < len(data) && data[end] == '\n' {
			end++
		}
		m[blk.Labels[0]] = rulePos{start: start, end: end}
	}
	return m, nil
}

func parseFile(path string) (map[string]rulePos, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	m, err := parseBytes(data)
	return m, data, err
}

func parseRule(snippet []byte) (string, error) {
	rs, err := rules.LoadHCLBytes(snippet)
	if err != nil {
		return "", err
	}
	if len(rs.Rules) != 1 {
		return "", errors.New("expected one rule")
	}
	return rs.Rules[0].ID, nil
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".admin-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}

	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.Chmod(name, mode); err != nil {
		_ = os.Remove(name)
		return err
	}

	return os.Rename(name, path)
}
