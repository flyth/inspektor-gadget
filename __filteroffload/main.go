// Copyright 2025 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"

	expr2 "github.com/expr-lang/expr"
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/checker"
	"github.com/expr-lang/expr/compiler"
	"github.com/expr-lang/expr/conf"
	"github.com/expr-lang/expr/file"
	"github.com/expr-lang/expr/optimizer"
	"github.com/expr-lang/expr/vm"
	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/expr"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

type Constraints struct {
	MinValue   any
	MaxValue   any
	ExactValue any
	Values     []any
	node       *ast.Node
}

type OffloadCallback func(*Constraints) (bool, error)

type offloader struct {
	offloaders  map[string][]OffloadCallback
	constraints map[string]*Constraints
}

func (o *offloader) registerEquals(node *ast.Node, identifier string, value any) {
	c, ok := o.constraints[identifier]
	if !ok {
		c = &Constraints{}
		o.constraints[identifier] = c
	}
	c.ExactValue = value
	c.node = node
}

type firstVisitor struct {
	*offloader
}

func (o *firstVisitor) Visit(node *ast.Node) {
	switch nx := (*node).(type) {
	case *ast.BinaryNode:
		switch nx.Operator {
		case "==":
			log.Printf("LEFT %+v", nx.Left.String())
			log.Printf("RIGH %T", nx.Right)
			// check if any side of the operation is an identifier and the other a constant
			if identifier, ok := nx.Left.(*ast.IdentifierNode); ok {
				if constant, ok := nx.Right.(*ast.ConstantNode); ok {
					log.Printf("checking %q against constant %+v", identifier, constant.Value)
					o.registerEquals(node, identifier.Value, constant.Value)
				}
				if constant, ok := nx.Right.(*ast.StringNode); ok {
					log.Printf("checking %q against string %+v", identifier, constant.Value)
					o.registerEquals(node, identifier.Value, constant.Value)
				}
			}
			if identifier, ok := nx.Right.(*ast.IdentifierNode); ok {
				if constant, ok := nx.Left.(*ast.ConstantNode); ok {
					log.Printf("checking %q against constant %+v", identifier, constant.Value)
					o.registerEquals(node, identifier.Value, constant.Value)
				}
				if constant, ok := nx.Left.(*ast.StringNode); ok {
					log.Printf("checking %q against string %+v", identifier, constant.Value)
					o.registerEquals(node, identifier.Value, constant.Value)
				}
			}
		}
	case *ast.IdentifierNode:
		log.Printf("%s", nx.String())
	}
}

type secondVisitor struct {
	*offloader
	done bool
}

func (o *secondVisitor) Visit(node *ast.Node) {
	if o.done {
		return
	}
	o.done = true
	o.Offload()
}

func (o *offloader) Offload() error {
	for name, constraint := range o.constraints {
		log.Printf("trying to offload %q", name)
		for _, cb := range o.offloaders[name] {
			log.Printf("> CB")
			ok, err := cb(constraint)
			if err != nil {
				log.Printf("failed to offload constraint %q: %v", name, err)
				return err
			}
			if ok {
				// Assume true, e.g. only already filtered entries will arrive
				ast.Patch(constraint.node, &ast.ConstantNode{Value: true})
				break
			}
		}
	}
	return nil
}

func (o *offloader) RegisterOffloader(name string, cb OffloadCallback) {
	o.offloaders[name] = append(o.offloaders[name], cb)
}

func main() {
	ds, _ := datasource.New(datasource.TypeSingle, "Main")
	field1, _ := ds.AddField("container", api.Kind_String)
	field2, _ := ds.AddField("pid", api.Kind_Uint32)

	op := &OffloadPatcher{
		visited:    make(map[*ast.Node]struct{}),
		offloaders: make(map[string][]*OffloadInfo),
	}

	op.RegisterOffloader("container", ContainerOffloader())
	op.RegisterOffloader("pid", ParamOffloader())

	dsp := expr.DSPatcher{
		Datasource: ds,
	}

	options := expr.GetBuiltInExpressions()
	options = append(options, expr2.AsBool(), expr2.Env(datasource.Data(nil))) // expr2.Patch(dsp),

	cf, err := Compile("container == 'a' || (container == 'b' && pid == 1)", op, dsp, options...)
	//	cf, err := expr.CompileFilterProgram(ds, "container == 'a' || (container == 'b' && pid == 1)", expr2.Patch(op))
	// cf, err := expr.CompileFilterProgram(ds, "field1 == 'a' || field1 == 'b'", expr2.Patch(&firstVisitor{offloader: offloader}), expr2.Patch(&secondVisitor{offloader: offloader}))
	if err != nil {
		log.Fatal(err)
	}

	d, _ := ds.NewPacketSingle()
	field1.PutString(d, "a")
	field2.PutUint32(d, uint32(100))

	log.Print(cf.Disassemble())

	res, err := expr.Run(cf, d)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(res)
}

// Compile parses and compiles given input expression to bytecode program.
func Compile(input string, op, dsp ast.Visitor, ops ...expr2.Option) (*vm.Program, error) {
	config := conf.CreateNew()
	for _, op := range ops {
		op(config)
	}
	for name := range config.Disabled {
		delete(config.Builtins, name)
	}
	config.Check()

	config.Strict = false

	tree, err := checker.ParseCheck(input, config)
	if err != nil {
		return nil, err
	}

	Walk(&tree.Node, op)
	ast.Walk(&tree.Node, dsp)

	if config.Optimize {
		err = optimizer.Optimize(&tree.Node, config)
		if err != nil {
			var fileError *file.Error
			if errors.As(err, &fileError) {
				return nil, fileError.Bind(tree.Source)
			}
			return nil, err
		}
	}

	program, err := compiler.Compile(tree, config)
	if err != nil {
		return nil, err
	}

	return program, nil
}

// Walk replaces ast.Walk because it first walks the node itself BEFORE branching out.
func Walk(node *ast.Node, v ast.Visitor) {
	v.Visit(node)
	if *node == nil {
		return
	}
	switch n := (*node).(type) {
	case *ast.NilNode:
	case *ast.IdentifierNode:
	case *ast.IntegerNode:
	case *ast.FloatNode:
	case *ast.BoolNode:
	case *ast.StringNode:
	case *ast.ConstantNode:
	case *ast.UnaryNode:
		Walk(&n.Node, v)
	case *ast.BinaryNode:
		Walk(&n.Left, v)
		Walk(&n.Right, v)
	case *ast.ChainNode:
		Walk(&n.Node, v)
	case *ast.MemberNode:
		Walk(&n.Node, v)
		Walk(&n.Property, v)
	case *ast.SliceNode:
		Walk(&n.Node, v)
		if n.From != nil {
			Walk(&n.From, v)
		}
		if n.To != nil {
			Walk(&n.To, v)
		}
	case *ast.CallNode:
		Walk(&n.Callee, v)
		for i := range n.Arguments {
			Walk(&n.Arguments[i], v)
		}
	case *ast.BuiltinNode:
		for i := range n.Arguments {
			Walk(&n.Arguments[i], v)
		}
	case *ast.PredicateNode:
		Walk(&n.Node, v)
	case *ast.PointerNode:
	case *ast.VariableDeclaratorNode:
		Walk(&n.Value, v)
		Walk(&n.Expr, v)
	case *ast.SequenceNode:
		for i := range n.Nodes {
			Walk(&n.Nodes[i], v)
		}
	case *ast.ConditionalNode:
		Walk(&n.Cond, v)
		Walk(&n.Exp1, v)
		Walk(&n.Exp2, v)
	case *ast.ArrayNode:
		for i := range n.Nodes {
			Walk(&n.Nodes[i], v)
		}
	case *ast.MapNode:
		for i := range n.Pairs {
			Walk(&n.Pairs[i], v)
		}
	case *ast.PairNode:
		Walk(&n.Key, v)
		Walk(&n.Value, v)
	default:
		panic(fmt.Sprintf("undefined node type (%T)", node))
	}
}
