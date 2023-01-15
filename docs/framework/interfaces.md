# Gadget Framework

## Interfaces

### Gadget Interface

This interface is used to transport metadata about a gadget and also instantiate it, if necessary.

### Trace Interface

#### TraceStartStop

* Start() error
* Stop()

#### TraceClose

* Close()

#### TraceResult

* Result() ([]byte, error)

#### OutputTransformer

> If not present, will assume to return printable result on Result()

* TransformOutput([]byte, string, params.Params) ([]byte, error)