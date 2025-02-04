<img src="assets/logotype.svg?raw=true" width="60%"  />

---

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Build](https://github.com/marinoandrea/hoppipolla/actions/workflows/build.yml/badge.svg)](.github/workflows/build.yml)
[![Test](https://github.com/marinoandrea/hoppipolla/actions/workflows/test.yml/badge.svg)](.github/workflows/test.yml)

> [!WARNING]  
> This software is in early phase of development and is not ready for
> production environments.

Hoppipolla (Icelandic for _"hopping into puddles"_) is a distributed framework
for user-side responsible networking based on the SCION Internet protocol. It implements
part of the [Responsible Internet proposal](https://link.springer.com/article/10.1007/s10922-020-09564-7)
with an approach inspired by the architecture designed in the [Accounting Value Effects for Responsible Networking
](https://doi.org/10.1145/3472951.3473507) paper and by the [User-driven Path verification and control for Inter-domain networks](https://upin-project.nl/) (UPIN) project.

Once installed, Hoppipolla allows the user to publish policies expressed in
Answer Set Programming (ASP) to select network nodes (i.e., autonomous systems)
that comply with them when routing packets to other remote addresses in the
SCION network.

An example of such policy in natural language:

```
Do not route network traffic through AS nodes that operate in country X
```

Which, using the Hoppipolla-specific ASP syntax would look like:

```
:- chosen(AS, _, _, _), operates(AS, "X").
```

The framework consists of a suite of fully-containerized services.
All of the services expose a gRPC API defined in the [`proto`](proto) folder.

## Installation

### Dependencies

In terms of external dependencies, Hoppipolla depends exclusively on SCION. The
user is expected to provide an entrypoint to the SCION stack via a stable
connection to the SCION daemon.

Follow [this guide](https://docs.scionlab.org/content/install/) to install
SCION and use it within the SCIONLab testbed.

### Docker Compose

At this stage, Hoppipolla is not ready for production in a fully distributed
environment. However, for experimental work, one can run it using `docker compose`.
The repository contains a [`docker-compose.yml`](docker-compose.yml) file which
contains all the necessary services (including a policy database).
Simply set up the relevant environmental variables and then run:

```sh
docker compose up
```

You can find an example of the configuration options that can be passed to the
services in the [`.env.example`](.env.example) file.

> [!IMPORTANT]
> Most notably, the `HOPPIPOLLA_SCIOND_URI` env variable should be set to
> the address of the SCION daemon (e.g., 127.0.0.1:30255).

## Examples

The [`scenarios`](scenarios) folder contains usage examples using Go and the
gRPC API of the Hoppipolla services.

## Citation

> [!WARNING]  
> This study is under peer review.

## License

Hoppipolla is [GNU GPL v3.0 licensed](/blob/main/LICENSE).
