# ls3viewer

![Latest GitHub release](https://img.shields.io/github/release/mashiike/ls3viewer.svg)
![Github Actions test](https://github.com/mashiike/ls3viewer/workflows/Test/badge.svg?branch=main)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/mashiike/ls3viewer/blob/master/LICENSE)

ls3viewer is a simple viewer to easily browse S3 using AWS Lambda.
It is a simple viewer with Basic Authentication or Google Authentication.

## Install 

#### Homebrew (macOS and Linux)

```console
$ brew install mashiike/tap/ls3viewer
```

### Binary packages

[Releases](https://github.com/mashiike/ls3viewer/releases)

## How to use in local environment

```shell
$ ls3viewer --bucket-name infra-dev
```

access http://localhost:8080

## How to use on AWS Lambda runtime 

The executable binary can be launched as a bootstrap for Lambda.


deploy one lambda functions, ls3viewer in [lambda directory](lambda/)  
The example of lambda directory uses [lambroll](https://github.com/fujiwara/lambroll) for deployment.

For more information on the infrastructure around lambda functions, please refer to [example.tf](lambda/example.tf).

## LICENSE

MIT License

Copyright (c) 2022 IKEDA Masashi
