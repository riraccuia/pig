package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}

	typeList, files, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(files) == 0 {
		if f := os.Getenv("GOFILE"); f != "" {
			files = []string{f}
		}
	}
	if typeList == "" || len(files) == 0 {
		fmt.Fprintln(os.Stderr, "usage: gen_struct_tags -type Type[,Type...] [files...]")
		os.Exit(1)
	}

	if err := processFiles(splitTypes(typeList), files); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseArgs(args []string) (typeList string, files []string, err error) {
	fs := flag.NewFlagSet("gen_struct_tags", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	types := fs.String("type", "", "comma-separated struct type names")
	if err := fs.Parse(args); err != nil {
		return "", nil, err
	}
	return *types, fs.Args(), nil
}

func splitTypes(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

type generatedFile struct {
	path string
	data []byte
}

func processFiles(types, filenames []string) error {
	allow := toSet(types)
	if len(allow) == 0 {
		return fmt.Errorf("no types given")
	}

	var outFiles []generatedFile
	found := map[string]bool{}
	for _, name := range filenames {
		if shouldSkip(name) {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		generated, fileFound, err := generate(name, src, allow)
		if err != nil {
			return err
		}
		for t := range fileFound {
			found[t] = true
		}
		outFiles = append(outFiles, generated...)
	}

	var missing []string
	for _, t := range types {
		if !found[t] {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("type %s not found", strings.Join(missing, ", "))
	}

	for _, f := range outFiles {
		if err := os.WriteFile(f.path, f.data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func shouldSkip(path string) bool {
	base := filepath.Base(path)
	if strings.HasSuffix(base, "_test.go") {
		return true
	}
	return strings.HasPrefix(base, "zfielddocs_") && strings.HasSuffix(base, ".go")
}

func outputPath(src, typeName string) string {
	return filepath.Join(filepath.Dir(src), "zfielddocs_"+typeName+".go")
}

func generate(filename string, src []byte, allow map[string]bool) ([]generatedFile, map[string]bool, error) {
	pkg, structs, err := collectStructs(filename, src, allow)
	if err != nil {
		return nil, nil, err
	}
	found := map[string]bool{}
	var files []generatedFile
	for _, s := range structs {
		found[s.Name] = true
		out, err := buildSource(pkg, []structFields{s})
		if err != nil {
			return nil, nil, err
		}
		files = append(files, generatedFile{path: outputPath(filename, s.Name), data: out})
	}
	return files, found, nil
}

type parsedMeta struct {
	Default  string
	Optional bool
	Desc     string
	ok       bool
}

type structFields struct {
	Name   string
	Fields map[string]parsedMeta
}

func collectStructs(filename string, src []byte, allow map[string]bool) (string, []structFields, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.ParseComments)
	if err != nil {
		return "", nil, err
	}

	structs := indexStructs(file)
	mergeSiblings(filename, file.Name.Name, structs)

	var result []structFields
	for _, name := range slices.Sorted(maps.Keys(allow)) {
		st := structs[name]
		if st == nil {
			continue
		}
		fields := map[string]parsedMeta{}
		if err := flatten(st, "", structs, map[string]bool{name: true}, fields); err != nil {
			return "", nil, err
		}
		result = append(result, structFields{Name: name, Fields: fields})
	}
	return file.Name.Name, result, nil
}

func indexStructs(file *ast.File) map[string]*ast.StructType {
	out := map[string]*ast.StructType{}
	ast.Inspect(file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name == nil {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		out[ts.Name.Name] = st
		return true
	})
	return out
}

func mergeSiblings(filename, pkg string, structs map[string]*ast.StructType) {
	abs, err := filepath.Abs(filename)
	if err != nil {
		return
	}
	if _, err := os.Stat(abs); err != nil {
		return
	}
	entries, err := os.ReadDir(filepath.Dir(abs))
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(filepath.Dir(abs), e.Name())
		if shouldSkip(path) {
			continue
		}
		if path == abs {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
		if err != nil || file.Name.Name != pkg {
			continue
		}
		maps.Copy(structs, indexStructs(file))
	}
}

type parsedType struct {
	name   string
	slice  bool
	mmap   bool
	inline *ast.StructType
}

func parseType(expr ast.Expr) parsedType {
	switch e := expr.(type) {
	case *ast.StarExpr:
		return parseType(e.X)
	case *ast.Ident:
		return parsedType{name: e.Name}
	case *ast.ArrayType:
		inner := parseType(e.Elt)
		inner.slice = true
		return inner
	case *ast.MapType:
		inner := parseType(e.Value)
		inner.mmap = true
		return inner
	case *ast.StructType:
		return parsedType{inline: e}
	default:
		return parsedType{}
	}
}

func astFieldKey(f *ast.Field) (key string, skip bool, embed bool) {
	tag := ""
	if f.Tag != nil {
		raw, err := strconv.Unquote(f.Tag.Value)
		if err == nil {
			st := reflect.StructTag(raw)
			tag = st.Get("toml")
			if tag == "" {
				tag = st.Get("json")
			}
		}
	}
	if tag == "-" {
		return "", true, false
	}
	key, _, _ = strings.Cut(tag, ",")
	anonymous := len(f.Names) == 0
	if anonymous && key == "" {
		return "", false, true
	}
	if key == "" {
		return "", true, false
	}
	return key, false, false
}

func flatten(st *ast.StructType, path string, structs map[string]*ast.StructType, visiting map[string]bool, out map[string]parsedMeta) error {
	if st == nil || st.Fields == nil {
		return nil
	}
	for _, field := range st.Fields.List {
		key, skip, embed := astFieldKey(field)
		if skip {
			continue
		}
		pt := parseType(field.Type)
		meta, err := parseFieldComment(field)
		if err != nil {
			return fmt.Errorf("%s: %w", fieldName(field), err)
		}
		if embed {
			if err := recurse(pt, path, structs, visiting, out); err != nil {
				return err
			}
			continue
		}
		child := joinPath(path, key)
		if meta.ok {
			out[child] = meta
		}
		switch {
		case pt.slice:
			if err := recurse(pt, child+"[]", structs, visiting, out); err != nil {
				return err
			}
		case pt.mmap:
			if err := recurse(pt, child+".*", structs, visiting, out); err != nil {
				return err
			}
		default:
			if err := recurse(pt, child, structs, visiting, out); err != nil {
				return err
			}
		}
	}
	return nil
}

func recurse(pt parsedType, path string, structs map[string]*ast.StructType, visiting map[string]bool, out map[string]parsedMeta) error {
	if pt.inline != nil {
		return flatten(pt.inline, path, structs, visiting, out)
	}
	if pt.name == "" {
		return nil
	}
	st := structs[pt.name]
	if st == nil {
		return nil
	}
	if visiting[pt.name] {
		return nil
	}
	visiting[pt.name] = true
	err := flatten(st, path, structs, visiting, out)
	delete(visiting, pt.name)
	return err
}

func fieldName(f *ast.Field) string {
	if len(f.Names) == 0 {
		return "embedded field"
	}
	return f.Names[0].Name
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

const commonImport = "github.com/riraccuia/pig/pkg/common"

func buildSource(pkg string, structs []structFields) ([]byte, error) {
	needFmt := false
	for _, s := range structs {
		for _, m := range s.Fields {
			if m.Default != "" {
				needFmt = true
				break
			}
		}
	}

	var b strings.Builder
	b.WriteString("// Code generated by gen_struct_tags; DO NOT EDIT.\n\n")
	b.WriteString("package ")
	b.WriteString(pkg)
	b.WriteString("\n\n")
	if needFmt {
		b.WriteString("import (\n\t\"fmt\"\n\n\t\"")
		b.WriteString(commonImport)
		b.WriteString("\"\n)\n\n")
	} else {
		b.WriteString("import \"")
		b.WriteString(commonImport)
		b.WriteString("\"\n\n")
	}
	for i, s := range structs {
		if i > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "func (%s) DescribeFields() map[string]common.FieldMeta {\n", s.Name)
		b.WriteString("\treturn map[string]common.FieldMeta{\n")
		for _, field := range slices.Sorted(maps.Keys(s.Fields)) {
			fmt.Fprintf(&b, "\t\t%s: {%s},\n", strconv.Quote(field), formatMeta(s.Fields[field]))
		}
		b.WriteString("\t}\n")
		b.WriteString("}\n")
	}
	return format.Source([]byte(b.String()))
}

func formatMeta(m parsedMeta) string {
	var parts []string
	if m.Default != "" {
		parts = append(parts, "Default: fmt.Sprint("+m.Default+")")
	}
	if m.Optional {
		parts = append(parts, "Optional: true")
	}
	if m.Desc != "" {
		parts = append(parts, "Desc: "+strconv.Quote(m.Desc))
	}
	return strings.Join(parts, ", ")
}

func toSet(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out
}

func parseFieldComment(field *ast.Field) (parsedMeta, error) {
	lines := commentLines(field.Doc)
	if len(lines) == 0 {
		return parsedMeta{}, nil
	}

	var meta parsedMeta
	sawOptional := false
	for i, line := range lines {
		key, val, found := strings.Cut(line, "=")
		if !found {
			return parsedMeta{}, fmt.Errorf("expected default=, optional=, or desc=, got %q", line)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch key {
		case "default":
			if meta.Default != "" {
				return parsedMeta{}, fmt.Errorf("duplicate default=")
			}
			if _, err := parser.ParseExpr(val); err != nil {
				return parsedMeta{}, fmt.Errorf("default=%s: %w", val, err)
			}
			meta.Default = val
			meta.ok = true
		case "optional":
			if sawOptional {
				return parsedMeta{}, fmt.Errorf("duplicate optional=")
			}
			b, err := strconv.ParseBool(val)
			if err != nil {
				return parsedMeta{}, fmt.Errorf("optional=%s: %w", val, err)
			}
			meta.Optional = b
			sawOptional = true
			meta.ok = true
		case "desc":
			parts := []string{val}
			parts = append(parts, lines[i+1:]...)
			meta.Desc = strings.Join(strings.Fields(strings.Join(parts, " ")), " ")
			meta.ok = true
			return meta, nil
		default:
			return parsedMeta{}, fmt.Errorf("unknown field comment key %q", key)
		}
	}
	return meta, nil
}

func commentLines(g *ast.CommentGroup) []string {
	if g == nil {
		return nil
	}
	var lines []string
	for _, c := range g.List {
		text := strings.TrimSpace(stripCommentMarks(c.Text))
		if text == "" {
			continue
		}
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			lines = append(lines, line)
		}
	}
	return lines
}

func stripCommentMarks(s string) string {
	switch {
	case strings.HasPrefix(s, "//"):
		return strings.TrimPrefix(s, "//")
	case strings.HasPrefix(s, "/*"):
		s = strings.TrimPrefix(s, "/*")
		return strings.TrimSuffix(s, "*/")
	default:
		return s
	}
}
