# Filter Offloading System

This package demonstrates a mechanism for offloading parts of filter expressions to kernel space using eBPF programs.

## Overview

The filter offloading system allows for processing filter expressions like `pid == 1 || otherVal == 2` and determining which parts can be offloaded to the kernel space. This is particularly useful for performance optimization, as filtering in the kernel can significantly reduce the amount of data that needs to be processed in user space.

## Key Components

### Constraints

The system defines several types of constraints that can be offloaded:

- **EqualsConstraint**: For exact value matches (`field == value`)
- **RangeConstraint**: For value ranges (`field > min && field < max`)
- **SetConstraint**: For multiple possible values (`field == value1 || field == value2`)

Each constraint type implements the `Constraint` interface which provides methods for:
- Getting the constraint's name (the field it applies to)
- Getting the constraint's type
- Merging with other constraints

### Offloaders

Offloaders are responsible for determining if a specific constraint can be offloaded and for activating the offloading when needed. Each offloader provides:

- A `CheckCallback` that determines if a constraint can be offloaded
- An `OffloadCallback` that activates the offloading mechanism

The system currently includes two example offloaders:
- **ContainerOffloader**: For filtering container IDs
- **ParamOffloader**: For filtering process IDs (PIDs)

### AST Processing

The system processes the Abstract Syntax Tree (AST) of the filter expression to:

1. Identify comparison operations that could be offloaded
2. Check if the offloaders support these operations
3. Replace supported operations with `true` in the AST, as they will be handled by the kernel

## Logical Operations

The system handles logical operations (AND, OR) carefully:

- For `OR` operations:
  - Both sides must target the same field (e.g., `container == 'a' || container == 'b'`)
  - For equality constraints, these are combined into a set constraint
  - For range constraints on PIDs, the system supports special multi-range offloading (e.g., `pid < 100 || pid > 1000`)
- For `AND` operations:
  - If both constraints target different fields, both can be offloaded independently
  - If both target the same field, they must be mergeable (e.g., `pid > 10 && pid < 20`)
  - If the constraints are contradictory (e.g., `pid < 10 && pid > 20`), offloading is not possible

## Usage

To use the filter offloading system:

1. Create and register offloaders for the fields you want to support
2. Use the `OffloadPatcher` to process your filter expression
3. Apply the modified filter in user space, with the offloadable parts handled in kernel space

## Example

The `main.go` file includes examples of different filter expressions and demonstrates how the system processes them.

## Extending

To add support for new fields or constraint types:

1. Create a new offloader for your field
2. Implement the `CheckCallback` and `OffloadCallback` functions
3. Register your offloader with the `OffloadPatcher`

For more complex constraint types, you may need to extend the `Constraint` interface and add appropriate handling in the `IsOffloadable` method.

## Debugging and Logging

The system provides extensive logging to help debug offloading decisions:

### Log Format

The logging system uses prefixes to indicate the nature of messages:

- `CHECKING`: Indicates the system is evaluating a node or constraint
- `PROCESSING`: Shows detailed steps in processing a node
- `IDENTIFIED`: Reports successful identification of components
- `CREATED`: Indicates a new constraint has been created
- `ATTEMPTING`: Shows the system is trying to perform an operation
- `OFFLOAD FAILED`: Provides information about why offloading was not possible
- `❌`: Indicates a failure or rejection
- `✅`: Indicates a success or acceptance

### What Gets Logged

1. **AST Node Processing**: Each node in the AST is logged as it's processed
2. **Constraint Evaluation**: The system logs details about each constraint and whether it can be offloaded
3. **Offloader Decisions**: Each offloader logs its decision process and reasons for accepting or rejecting constraints
4. **Merging Operations**: When constraints need to be merged (in AND operations), the process and results are logged
5. **Activation Results**: The system logs which offloaders were successfully activated

### Using the Logs

When offloading isn't working as expected, examine the logs to identify:

- Which part of the filter expression couldn't be offloaded and why
- Whether the constraints were recognized but rejected by the offloaders
- If constraints couldn't be merged when using logical operators
- Whether offloader activation succeeded after constraint checking

The test cases in `main.go` demonstrate the logging system with various filter expressions.
