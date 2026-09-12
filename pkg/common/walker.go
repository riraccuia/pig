package common

import (
	"fmt"
	"reflect"
	"strings"
)

type FieldMeta struct {
	Default  string
	Optional bool
	Desc     string
}

type FieldDoc struct {
	Path        string
	Type        string
	Default     string
	Enum        []string
	Description string
	Optional    bool
	Ref         string
}

type TypeDoc struct {
	Name   string
	Fields []FieldDoc
}

func MapStruct(root any) []FieldDoc {
	t := unwrap(reflect.TypeOf(root))
	return walk(t, "", describeFields(t), map[reflect.Type]bool{})
}

func MapStructTypes(root any) []TypeDoc {
	t := unwrap(reflect.TypeOf(root))
	descs := describeFields(t)
	seen := map[reflect.Type]bool{}
	var out []TypeDoc
	queue := []typeJob{{t, ""}}
	for len(queue) > 0 {
		job := queue[0]
		queue = queue[1:]
		cur := unwrap(job.t)
		if cur == nil || cur.Kind() != reflect.Struct || cur.Name() == "" || seen[cur] {
			continue
		}
		seen[cur] = true
		fields, refs := walkDirect(cur, job.prefix, descs)
		out = append(out, TypeDoc{Name: cur.Name(), Fields: fields})
		queue = append(queue, refs...)
	}
	return out
}

type typeJob struct {
	t      reflect.Type
	prefix string
}

func namedStruct(t reflect.Type) bool {
	t = unwrap(t)
	return t != nil && t.Kind() == reflect.Struct && t.Name() != ""
}

func walkDirect(t reflect.Type, prefix string, descs map[string]FieldMeta) ([]FieldDoc, []typeJob) {
	var fields []FieldDoc
	var refs []typeJob
	for field := range t.Fields() {
		if !field.IsExported() {
			continue
		}
		key, skip, embed := fieldKey(field)
		if skip {
			continue
		}
		elem := unwrap(field.Type)
		if embed {
			sub, subRefs := walkDirect(elem, prefix, descs)
			fields = append(fields, sub...)
			refs = append(refs, subRefs...)
			continue
		}

		lookup := joinPath(prefix, key)
		meta := resolveMeta(lookup, field, descs)
		docs, more := directField(key, lookup, elem, field.Tag, meta, descs)
		fields = append(fields, docs...)
		refs = append(refs, more...)
	}
	return fields, refs
}

func directField(display, lookup string, elem reflect.Type, tag reflect.StructTag, meta FieldMeta, descs map[string]FieldMeta) ([]FieldDoc, []typeJob) {
	switch elem.Kind() {
	case reflect.Struct:
		if namedStruct(elem) {
			return []FieldDoc{newRefDoc(display, elem.Name(), tag, meta, elem.Name())},
				[]typeJob{{elem, lookup}}
		}
		docs := []FieldDoc{newDoc(display, "object", tag, meta)}
		sub, refs := walkDirect(elem, lookup, descs)
		for i := range sub {
			sub[i].Path = joinPath(display, sub[i].Path)
			docs = append(docs, sub[i])
		}
		return docs, refs
	case reflect.Slice, reflect.Array:
		inner := unwrap(elem.Elem())
		if namedStruct(inner) {
			return []FieldDoc{newRefDoc(display, "[]"+inner.Name(), tag, meta, inner.Name())},
				[]typeJob{{inner, lookup + "[]"}}
		}
		return []FieldDoc{newDoc(display, "[]"+userType(inner), tag, meta)}, nil
	case reflect.Map:
		key := userType(elem.Key())
		val := unwrap(elem.Elem())
		if namedStruct(val) {
			return []FieldDoc{newRefDoc(display, "map["+key+"]"+val.Name(), tag, meta, val.Name())},
				[]typeJob{{val, lookup + ".*"}}
		}
		return []FieldDoc{newDoc(display, userType(elem), tag, meta)}, nil
	default:
		return []FieldDoc{newDoc(display, userType(elem), tag, meta)}, nil
	}
}

func walk(t reflect.Type, path string, descs map[string]FieldMeta, visiting map[reflect.Type]bool) []FieldDoc {
	t = unwrap(t)
	if t == nil {
		return nil
	}

	switch t.Kind() {
	case reflect.Struct:
		return walkStruct(t, path, descs, visiting)
	case reflect.Slice, reflect.Array:
		return walkSlice(t, path, reflect.StructTag(""), FieldMeta{}, descs, visiting)
	case reflect.Map:
		return walkMap(t, path, reflect.StructTag(""), FieldMeta{}, descs, visiting)
	default:
		return []FieldDoc{newDoc(path, userType(t), reflect.StructTag(""), FieldMeta{})}
	}
}

func walkStruct(t reflect.Type, path string, descs map[string]FieldMeta, visiting map[reflect.Type]bool) []FieldDoc {
	if visiting[t] {
		return nil
	}
	visiting[t] = true
	defer delete(visiting, t)

	var docs []FieldDoc
	for field := range t.Fields() {
		docs = append(docs, walkField(field, path, descs, visiting)...)
	}
	return docs
}

func walkField(field reflect.StructField, parent string, descs map[string]FieldMeta, visiting map[reflect.Type]bool) []FieldDoc {
	if !field.IsExported() {
		return nil
	}

	key, skip, embed := fieldKey(field)
	if skip {
		return nil
	}

	elem := unwrap(field.Type)

	if embed {
		return walk(elem, parent, descs, visiting)
	}

	path := joinPath(parent, key)
	meta := resolveMeta(path, field, descs)

	switch elem.Kind() {
	case reflect.Struct:
		docs := []FieldDoc{newDoc(path, "object", field.Tag, meta)}
		return append(docs, walkStruct(elem, path, descs, visiting)...)
	case reflect.Slice, reflect.Array:
		return walkSlice(elem, path, field.Tag, meta, descs, visiting)
	case reflect.Map:
		return walkMap(elem, path, field.Tag, meta, descs, visiting)
	default:
		return []FieldDoc{newDoc(path, userType(elem), field.Tag, meta)}
	}
}

func walkSlice(t reflect.Type, path string, tag reflect.StructTag, meta FieldMeta, descs map[string]FieldMeta, visiting map[reflect.Type]bool) []FieldDoc {
	inner := unwrap(t.Elem())
	docs := []FieldDoc{newDoc(path, "[]"+userType(inner), tag, meta)}
	if inner.Kind() != reflect.Struct && inner.Kind() != reflect.Map {
		return docs
	}
	return append(docs, walk(inner, path+"[]", descs, visiting)...)
}

func walkMap(t reflect.Type, path string, tag reflect.StructTag, meta FieldMeta, descs map[string]FieldMeta, visiting map[reflect.Type]bool) []FieldDoc {
	docs := []FieldDoc{newDoc(path, userType(t), tag, meta)}
	val := unwrap(t.Elem())
	if val.Kind() != reflect.Struct {
		return docs
	}
	return append(docs, walkStruct(val, path+".*", descs, visiting)...)
}

func fieldKey(f reflect.StructField) (key string, skip bool, embed bool) {
	tag := f.Tag.Get("toml")
	if tag == "" {
		tag = f.Tag.Get("json")
	}
	if tag == "-" {
		return "", true, false
	}

	key, _, _ = strings.Cut(tag, ",")
	if f.Anonymous && key == "" {
		return "", false, true
	}
	if key == "" {
		return "", true, false
	}
	return key, false, false
}

func unwrap(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

type FieldDescriber interface {
	DescribeFields() map[string]FieldMeta
}

func describeFields(t reflect.Type) map[string]FieldMeta {
	t = unwrap(t)
	if t == nil || t.Kind() != reflect.Struct {
		return nil
	}
	zero := reflect.New(t).Elem()
	if d, ok := zero.Interface().(FieldDescriber); ok {
		return d.DescribeFields()
	}
	ptr := reflect.New(t)
	if d, ok := ptr.Interface().(FieldDescriber); ok {
		return d.DescribeFields()
	}
	return nil
}

func resolveMeta(path string, field reflect.StructField, descs map[string]FieldMeta) FieldMeta {
	meta, inMap := descs[path]
	if meta.Desc == "" {
		meta.Desc = field.Tag.Get("desc")
	}
	if meta.Default == "" {
		meta.Default = field.Tag.Get("default")
	}
	if !inMap {
		meta.Optional = field.Tag.Get("optional") == "true" || field.Type.Kind() == reflect.Ptr
	}
	return meta
}

func newDoc(path, typeName string, tag reflect.StructTag, meta FieldMeta) FieldDoc {
	return newRefDoc(path, typeName, tag, meta, "")
}

func newRefDoc(path, typeName string, tag reflect.StructTag, meta FieldMeta, ref string) FieldDoc {
	return FieldDoc{
		Path:        path,
		Type:        typeName,
		Default:     meta.Default,
		Enum:        splitCSV(tag.Get("enum")),
		Description: meta.Desc,
		Optional:    meta.Optional,
		Ref:         ref,
	}
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func userType(t reflect.Type) string {
	t = unwrap(t)
	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		return "[]" + userType(t.Elem())
	case reflect.Map:
		return "map[" + userType(t.Key()) + "]" + userType(t.Elem())
	case reflect.Struct:
		return "object"
	case reflect.Interface:
		return "any"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "int"
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "uint"
	case reflect.Float32, reflect.Float64:
		return "float"
	default:
		return t.Kind().String()
	}
}

func GenerateMarkdownTable(types []TypeDoc) string {
	var b strings.Builder
	for i, td := range types {
		if i > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "## %s\n\n", td.Name)
		b.WriteString("| Field | Type | Optional | Default | Description |\n")
		b.WriteString("| --- | --- | --- | --- | --- |\n")
		for _, d := range td.Fields {
			def := d.Default
			if def == "" {
				def = "-"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n",
				mdCell(d.Path),
				mdTypeCell(d),
				mdCell(fmt.Sprintf("%t", d.Optional)),
				mdCell(def),
				mdCell(d.Description),
			)
		}
	}
	return b.String()
}

func GenerateCLIDoc(types []TypeDoc) string {
	var b strings.Builder
	for i, td := range types {
		if i > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "%s\n", td.Name)
		rows := [][]string{{"Field", "Type", "Optional", "Default", "Description"}}
		for _, d := range td.Fields {
			def := d.Default
			if def == "" {
				def = "-"
			}
			rows = append(rows, []string{
				d.Path,
				typeLabel(d),
				fmt.Sprintf("%t", d.Optional),
				def,
				strings.ReplaceAll(d.Description, "\n", " "),
			})
		}
		b.WriteString(formatTable(rows))
	}
	return b.String()
}

func formatTable(rows [][]string) string {
	cols := len(rows[0])
	last := cols - 1
	widths := make([]int, cols)
	for _, r := range rows {
		for i := range last {
			widths[i] = max(widths[i], len(r[i]))
		}
	}
	sum := 0
	for _, n := range widths[:last] {
		sum += n
	}
	lastColMaxWidth := 0
	for _, r := range rows {
		lastColMaxWidth = max(lastColMaxWidth, len(r[last]))
	}
	widths[last] = min(TerminalWidth(0)-sum-(3*cols+1), lastColMaxWidth)

	var b strings.Builder
	rule := func() {
		b.WriteByte('+')
		for _, n := range widths {
			b.WriteString(strings.Repeat("-", n+2))
			b.WriteByte('+')
		}
		b.WriteByte('\n')
	}
	write := func(r []string) {
		for i, c := range r {
			fmt.Fprintf(&b, "| %-*s ", widths[i], c)
		}
		b.WriteString("|\n")
	}

	rule()
	write(rows[0])
	rule()
	for _, r := range rows[1:] {
		lines := strings.Split(WrapText(r[last], "", false, widths[last]), "\n")
		r[last] = lines[0]
		write(r)
		for _, line := range lines[1:] {
			cont := make([]string, cols)
			cont[last] = line
			write(cont)
		}
	}
	rule()
	return b.String()
}

func mdTypeCell(d FieldDoc) string {
	label := d.Type
	if d.Ref != "" {
		link := fmt.Sprintf("[%s](#%s)", d.Ref, markdownAnchor(d.Ref))
		label = strings.Replace(label, d.Ref, link, 1)
	}
	if d.Optional {
		label += "?"
	}
	if len(d.Enum) > 0 {
		label += " (" + strings.Join(d.Enum, ", ") + ")"
	}
	return label
}

func markdownAnchor(s string) string {
	return strings.ToLower(s)
}

func mdCell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "|", "\\|")
}

func typeLabel(d FieldDoc) string {
	s := d.Type
	if d.Optional {
		s += "?"
	}
	if len(d.Enum) > 0 {
		s += " (" + strings.Join(d.Enum, ", ") + ")"
	}
	return s
}
