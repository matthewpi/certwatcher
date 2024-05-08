# Certificate Watcher

[![Godoc Reference][pkg.go.dev_img]][pkg.go.dev]
[![Pipeline Status][pipeline_img  ]][pipeline  ]

Go package that provides the ability to hot-reload TLS certificates without downtime.

[pkg.go.dev]:     https://pkg.go.dev/github.com/matthewpi/certwatcher
[pkg.go.dev_img]: https://img.shields.io/badge/%E2%80%8B-reference-007d9c?logo=go&logoColor=white&style=flat-square

[pipeline]:     https://github.com/matthewpi/certwatcher/actions/workflows/test.yml
[pipeline_img]: https://img.shields.io/github/actions/workflow/status/matthewpi/certwatcher/ci.yaml?style=flat-square&label=tests

## Usage

> TODO: add usage

## Installation

```bash
go get github.com/matthewpi/certwatcher
```

## Licensing

All code in this repository is licensed under the [MIT license](./LICENSE) with two exceptions.

Code under [`internal/sets`](./internal/sets/LICENSE) and [`internal/wait`](./internal/wait/LICENSE)
is licensed under the [Apache 2.0 license](./internal/sets/LICENSE) as a majority of the code was
sourced from libraries of Kubernetes and was put in-tree to guarantee API stability and reduce the
number of external dependencies necessary for this library to function. Thank you to the developers
who made those wonderful utilities.
