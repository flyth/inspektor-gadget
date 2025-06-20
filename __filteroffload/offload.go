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
	"github.com/expr-lang/expr/ast"
	log "github.com/sirupsen/logrus"
)

var comparisonOperators = map[string]bool{
	"==": true,
	"!=": true,
	">":  true,
	">=": true,
	"<":  true,
	"<=": true,
}

var logicalOperators = map[string]bool{
	"||": true,
	"&&": true,
}

type Constraint interface {
	Name() string
}

type constraint struct {
	name string
}

func (c *constraint) Name() string {
	return c.name
}

type EqualsConstraint struct {
	constraint
	Value any
}

type OffloadInfo struct {
	Name            string
	CheckCallback   func(any) (bool, error)
	OffloadCallback func(any) (bool, error)
}

type OffloadPatcher struct {
	visited    map[*ast.Node]struct{}
	offloaders map[string][]*OffloadInfo
}

func (o *OffloadPatcher) CheckOffload(name string, constraint any) (bool, error) {
	log.Printf("checking constraint %q %+v", name, constraint)
	for _, offload := range o.offloaders[name] {
		ok, err := offload.CheckCallback(constraint)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func (o *OffloadPatcher) IsOffloadable(node *ast.Node) (bool, Constraint) {
	o.visited[node] = struct{}{}
	switch nx := (*node).(type) {
	case *ast.BinaryNode:
		if comparisonOperators[nx.Operator] {
			log.Printf("checking comparison")
			var identifier *ast.IdentifierNode
			var other ast.Node
			var value any
			// One side must be a constant
			if tmpIdentifier, ok := nx.Left.(*ast.IdentifierNode); ok {
				identifier = tmpIdentifier
				other = nx.Right
			} else if tmpIdentifier, ok := nx.Right.(*ast.IdentifierNode); ok {
				identifier = tmpIdentifier
				other = nx.Left
			}
			if identifier == nil {
				return false, nil
			}
			switch on := other.(type) {
			default:
				return false, nil
			case *ast.StringNode:
				value = on.Value
			case *ast.IntegerNode:
				value = on.Value
			case *ast.FloatNode:
				value = on.Value
			case *ast.BoolNode:
				value = on.Value
			}
			switch nx.Operator {
			case "==":
				constraint := &EqualsConstraint{
					constraint: constraint{
						name: identifier.Value,
					},
					Value: value,
				}
				offloadable, err := o.CheckOffload(identifier.Value, constraint)
				if err != nil {
					return false, nil
				}
				return offloadable, constraint
			}
			return false, nil
		}
		if logicalOperators[nx.Operator] {
			// && or ||: both sides must be offloadable
			log.Printf("checking logical")
			ok1, c1 := o.IsOffloadable(&nx.Left)
			ok2, c2 := o.IsOffloadable(&nx.Right)
			if !ok1 || !ok2 {
				return false, nil
			}
			if nx.Operator == "||" {
				// constraints MUST both be of the same type
				if c1.Name() != c2.Name() {
					return false, nil
				}
			}
			if nx.Operator == "&&" {
				// constraints MUST both be of the same type AND share the same value
				// or NOT be of the same type
				return false, nil
			}
		}
		return false, nil
	case *ast.UnaryNode:
		return o.IsOffloadable(&nx.Node)
	default:
		return false, nil
	}
}

func (o *OffloadPatcher) RegisterOffloader(name string, oi *OffloadInfo) {
	o.offloaders[name] = append(o.offloaders[name], oi)
}

func (o *OffloadPatcher) Visit(node *ast.Node) {
	if _, ok := o.visited[node]; ok {
		return
	}
	log.Printf("> visiting offload node %T %+v", *node, *node)
	if ok, c := o.IsOffloadable(node); ok {
		log.Printf("offloading node %q %+v", c.Name(), c)
		ast.Patch(node, &ast.ConstantNode{Value: true})
	}
	log.Printf("< visiting offload node %T", *node)
}
