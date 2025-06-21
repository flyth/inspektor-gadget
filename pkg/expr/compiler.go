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

package expr

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

// Compile parses and compiles the given input expression to a bytecode program.
// It applies the provided visitors to the AST before compilation.
//
// Parameters:
//   - input: The expression string to compile
//   - op: The first visitor to apply to the AST (typically an OffloadPatcher)
//   - dsp: The second visitor to apply to the AST (typically a DSPatcher)
//   - ops: Additional options for the expression compiler
//
// Returns:
//   - A compiled program that can be executed
//   - An error if compilation fails
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
// This is important for the offloading process to work correctly.
//
// Parameters:
//   - node: The AST node to walk
//   - v: The visitor to apply to each node
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
