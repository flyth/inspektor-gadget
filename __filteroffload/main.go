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
)

// func mainX() {
// 	ds, _ := datasource.New(datasource.TypeSingle, "Main")
// 	containerField, _ := ds.AddField("container", api.Kind_String)
// 	pidField, _ := ds.AddField("pid", api.Kind_Uint32)
// 	commField, _ := ds.AddField("command", api.Kind_String)
//
// 	// Create the offloader with our enhanced patcher
// 	op := NewOffloadPatcher()
//
// 	// Register offloaders for the fields we support
// 	op.RegisterOffloader("container", ContainerOffloader())
// 	op.RegisterOffloader("pid", ParamOffloader())
//
// 	// Create the datasource patcher
// 	dsp := expr.DSPatcher{
// 		Datasource: ds,
// 	}
//
// 	// Get expression options
// 	options := expr.GetBuiltInExpressions()
// 	options = append(options, expr2.AsBool(), expr2.Env(datasource.Data(nil)))
//
// 	// Test with a few different filter expressions to demonstrate the behavior
// 	testFilters := []struct {
// 		name        string
// 		filter      string
// 		expectation string
// 	}{
// 		{
// 			name:        "Simple equality offloadable",
// 			filter:      "container == 'a'",
// 			expectation: "Container offload should work",
// 		},
// 		{
// 			name:        "OR with same field offloadable",
// 			filter:      "container == 'a' || container == 'b'",
// 			expectation: "Container offload should work as a set",
// 		},
// 		{
// 			name:        "AND with different fields offloadable",
// 			filter:      "container == 'a' && pid == 1",
// 			expectation: "Both container and PID offloads should work",
// 		},
// 		{
// 			name:        "AND with range offloadable",
// 			filter:      "pid > 100 && pid < 1000",
// 			expectation: "PID range offload should work",
// 		},
// 		{
// 			name:        "Mixed with non-offloadable part",
// 			filter:      "container == 'a' || (command == 'test' && pid == 1)",
// 			expectation: "Only container part should be offloadable",
// 		},
// 		{
// 			name:        "Complex filter with multiple parts",
// 			filter:      "(container == 'a' || container == 'b') && (pid < 100 || pid > 1000)",
// 			expectation: "Container and PID parts should be handled separately",
// 		},
// 		{
// 			name:        "Contradictory constraints",
// 			filter:      "pid < 10 && pid > 20",
// 			expectation: "Should not be offloadable due to contradiction",
// 		},
// 	}
//
// 	// Try each test case
// 	for i, testFilter := range testFilters {
// 		log.Printf("\n\n==============================================================")
// 		log.Printf("TEST CASE %d: %s", i, testFilter.name)
// 		log.Printf("FILTER: %s", testFilter.filter)
// 		log.Printf("EXPECTATION: %s", testFilter.expectation)
// 		log.Printf("==============================================================\n")
//
// 		// Reset offloader for each test
// 		op := &OffloadPatcher{
// 			visited:    make(map[*ast.Node]struct{}),
// 			offloaders: make(map[string][]*OffloadInfo),
// 			activated:  make(map[string]bool),
// 		}
//
// 		// Register offloaders
// 		op.RegisterOffloader("container", ContainerOffloader())
// 		op.RegisterOffloader("pid", ParamOffloader())
//
// 		// Parse and compile the filter expression
// 		cf, err := Compile(testFilter.filter, op, dsp, options...)
// 		if err != nil {
// 			log.Printf("❌ ERROR compiling filter: %v", err)
// 			continue
// 		}
//
// 		// Create a test packet
// 		d, _ := ds.NewPacketSingle()
// 		containerField.PutString(d, "a")
// 		pidField.PutUint32(d, uint32(1))
// 		commField.PutString(d, "test")
//
// 		// Log which offloaders were activated
// 		log.Printf("\nOFFLOADING RESULT:")
// 		if len(op.activated) == 0 {
// 			log.Printf("❌ No offloaders were activated")
// 		} else {
// 			log.Printf("✅ Activated offloaders:")
// 			for name, activated := range op.activated {
// 				if activated {
// 					log.Printf("  - %s", name)
// 				}
// 			}
// 		}
//
// 		// Run the filter and show the result
// 		res, err := expr.Run(cf, d)
// 		if err != nil {
// 			log.Printf("❌ ERROR running filter: %v", err)
// 			continue
// 		}
// 		log.Printf("\nFilter result with test data: %v", res)
//
// 		// Only show disassembly when verbose logging is needed
// 		// log.Printf("\nCompiled program:")
// 		// log.Print(cf.Disassemble())
//
// 		log.Printf("\nTEST CASE %d COMPLETE\n", i)
// 	}
//
// 	// Show summary
// 	log.Printf("\n\n==============================================================")
// 	log.Printf("SUMMARY: All %d test cases completed", len(testFilters))
// 	log.Printf("==============================================================\n")
// }

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

	// First pass: let our offloader visit each node
	Walk(&tree.Node, op)

	// Second pass: normal AST walking for the DSPatcher
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
