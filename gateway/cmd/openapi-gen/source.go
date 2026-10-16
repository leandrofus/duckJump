package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	opMarker     = "openapi:operation"
	schemaMarker = "openapi:schema "
)

type source struct {
	fset  *token.FileSet
	files []*ast.File
	// handlers: methods with a *Server receiver in package server.
	handlers map[string]*ast.FuncDecl
	fileOf   map[*ast.FuncDecl]*ast.File
}

func parseTree(dir string) (*source, error) {
	src := &source{fset: token.NewFileSet(), handlers: map[string]*ast.FuncDecl{}, fileOf: map[*ast.FuncDecl]*ast.File{}}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(src.fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		src.files = append(src.files, f)
		if f.Name.Name != "server" {
			return nil
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || len(fd.Recv.List) != 1 {
				continue
			}
			if star, ok := fd.Recv.List[0].Type.(*ast.StarExpr); ok {
				if id, ok := star.X.(*ast.Ident); ok && id.Name == "Server" {
					src.handlers[fd.Name.Name] = fd
					src.fileOf[fd] = f
				}
			}
		}
		return nil
	})
	return src, err
}

// ---- routes ----

type access int

const (
	accessPublic access = iota
	accessRoles
	accessPending
)

type route struct {
	method, path, handler string
	access                access
	roles                 []string
	allRoles              int
}

// roleSets reads `name = roleSet{"a": true, ...}` declarations.
func (s *source) roleSets() map[string][]string {
	out := map[string][]string{}
	for _, f := range s.files {
		if f.Name.Name != "server" {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			for i, v := range vs.Values {
				cl, ok := v.(*ast.CompositeLit)
				if !ok {
					continue
				}
				if t, ok := cl.Type.(*ast.Ident); !ok || t.Name != "roleSet" {
					continue
				}
				var roles []string
				for _, e := range cl.Elts {
					if kv, ok := e.(*ast.KeyValueExpr); ok {
						if lit, ok := kv.Key.(*ast.BasicLit); ok {
							r, _ := strconv.Unquote(lit.Value)
							roles = append(roles, r)
						}
					}
				}
				sort.Strings(roles)
				out[vs.Names[i].Name] = roles
			}
			return true
		})
	}
	return out
}

func selectorName(e ast.Expr) (string, bool) {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	return sel.Sel.Name, true
}

// routes reads every mux.Handle / mux.HandleFunc call in Server.Handler.
func (s *source) routes() ([]route, []string) {
	h, ok := s.handlers["Handler"]
	if !ok {
		return nil, []string{"Server.Handler not found"}
	}
	sets := s.roleSets()
	all := 0
	for _, r := range sets {
		all = max(all, len(r))
	}
	var out []route
	var errs []string
	ast.Inspect(h.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn, ok := selectorName(call.Fun)
		if !ok || (fn != "Handle" && fn != "HandleFunc") || len(call.Args) != 2 {
			return true
		}
		pos := s.fset.Position(call.Pos())
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			errs = append(errs, fmt.Sprintf("%s: route pattern is not a string literal", pos))
			return false
		}
		pattern, _ := strconv.Unquote(lit.Value)
		method, path, hasMethod := strings.Cut(pattern, " ")
		if !hasMethod {
			return false // catch-alls without a method are not operations
		}
		if !strings.HasPrefix(path, "/api/") {
			return false // the UI and other non-API routes are not part of the contract
		}
		r := route{method: method, path: path, allRoles: all}
		switch arg := call.Args[1].(type) {
		case *ast.SelectorExpr: // s.handler: public
			r.handler = arg.Sel.Name
		case *ast.CallExpr:
			wrap, _ := selectorName(arg.Fun)
			if len(arg.Args) == 0 {
				errs = append(errs, fmt.Sprintf("%s: %s() takes no handler", pos, wrap))
				return false
			}
			last := arg.Args[len(arg.Args)-1]
			r.handler, _ = selectorName(last)
			switch wrap {
			case "authed":
				id, ok := arg.Args[0].(*ast.Ident)
				roles, known := sets[id.Name]
				if !ok || !known {
					errs = append(errs, fmt.Sprintf("%s: unknown role set", pos))
					return false
				}
				r.access, r.roles = accessRoles, roles
			case "pending":
				r.access = accessPending
			default:
				errs = append(errs, fmt.Sprintf("%s: unknown wrapper %s", pos, wrap))
				return false
			}
		default:
			errs = append(errs, fmt.Sprintf("%s: unrecognized handler expression", pos))
			return false
		}
		if r.handler == "" {
			errs = append(errs, fmt.Sprintf("%s: cannot resolve handler", pos))
			return false
		}
		out = append(out, r)
		return false
	})
	return out, errs
}

// ---- comment blocks ----

func lines(cg *ast.CommentGroup) []string {
	var out []string
	for _, c := range cg.List {
		t := strings.TrimPrefix(c.Text, "//")
		t = strings.TrimPrefix(t, " ")
		out = append(out, t)
	}
	return out
}

// operationBlock finds the `openapi:operation` group between the previous
// declaration and the handler.
func (s *source) operationBlock(handler string) (string, bool) {
	fd, ok := s.handlers[handler]
	if !ok {
		return "", false
	}
	f := s.fileOf[fd]
	var lowest token.Pos
	for _, d := range f.Decls {
		if d.End() < fd.Pos() && d.End() > lowest {
			lowest = d.End()
		}
	}
	for i := len(f.Comments) - 1; i >= 0; i-- {
		cg := f.Comments[i]
		if cg.End() >= fd.Pos() || cg.Pos() <= lowest {
			continue
		}
		ls := lines(cg)
		if len(ls) > 0 && strings.TrimSpace(ls[0]) == opMarker {
			return strings.Join(ls[1:], "\n"), true
		}
	}
	return "", false
}

// schemas collects `openapi:schema Name` blocks and checks each block bound
// to a struct (the nearest schema block above the type declaration) against
// the struct's JSON field names.
func (s *source) schemas() (map[string]any, []string) {
	out := map[string]any{}
	var errs []string
	for _, f := range s.files {
		type block struct {
			name string
			cg   *ast.CommentGroup
			body map[string]any
		}
		var blocks []block
		for _, cg := range f.Comments {
			ls := lines(cg)
			if len(ls) == 0 || !strings.HasPrefix(strings.TrimSpace(ls[0]), schemaMarker) {
				continue
			}
			name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(ls[0]), schemaMarker))
			var body map[string]any
			if err := yaml.Unmarshal([]byte(strings.Join(ls[1:], "\n")), &body); err != nil {
				errs = append(errs, fmt.Sprintf("schema %s (%s): %v", name, s.fset.Position(cg.Pos()), err))
				continue
			}
			if err := suspiciousKeys(body); err != nil {
				errs = append(errs, fmt.Sprintf("schema %s: %v", name, err))
			}
			if _, dup := out[name]; dup {
				errs = append(errs, fmt.Sprintf("schema %s defined twice", name))
			}
			out[name] = body
			blocks = append(blocks, block{name, cg, body})
		}
		// Bind blocks to struct declarations.
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE || len(gd.Specs) != 1 {
				continue
			}
			ts := gd.Specs[0].(*ast.TypeSpec)
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				continue
			}
			var prevEnd token.Pos
			for _, o := range f.Decls {
				if o.End() < gd.Pos() && o.End() > prevEnd {
					prevEnd = o.End()
				}
			}
			var bound *block
			for i := range blocks {
				b := &blocks[i]
				if b.cg.End() < gd.Pos() && b.cg.Pos() > prevEnd && (bound == nil || b.cg.End() > bound.cg.End()) {
					bound = b
				}
			}
			if bound == nil {
				continue
			}
			if e := compareFields(bound.name, ts.Name.Name, st, bound.body); e != "" {
				errs = append(errs, e)
			}
		}
	}
	return out, errs
}

func compareFields(schema, typ string, st *ast.StructType, body map[string]any) string {
	props, _ := body["properties"].(map[string]any)
	want := map[string]bool{}
	for k := range props {
		want[k] = true
	}
	have := map[string]bool{}
	for _, fld := range st.Fields.List {
		if fld.Tag == nil {
			continue
		}
		tag, _ := strconv.Unquote(fld.Tag.Value)
		name := strings.Split(reflect.StructTag(tag).Get("json"), ",")[0]
		if name != "" && name != "-" {
			have[name] = true
		}
	}
	var missing, extra []string
	for k := range have {
		if !want[k] {
			missing = append(missing, k)
		}
	}
	for k := range want {
		if !have[k] {
			extra = append(extra, k)
		}
	}
	if len(missing) == 0 && len(extra) == 0 {
		return ""
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return fmt.Sprintf("schema %s vs struct %s: not in schema %v, not in struct %v", schema, typ, missing, extra)
}
