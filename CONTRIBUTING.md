# Contributing to Namira Core

First off, thanks for taking the time to contribute! :tada:

The following is a set of guidelines for contributing to the project. These guidelines are not hard rules; use your best judgment and feel free to propose changes to this document via pull‑request.

---

## Table of Contents

- [Contributing to Namira Core](#contributing-to-namira-core)
  - [Table of Contents](#table-of-contents)
  - [Getting Started](#getting-started)
  - [Bug Reports](#bug-reports)
  - [Feature Requests](#feature-requests)
  - [Pull Requests](#pull-requests)
  - [Coding Guidelines](#coding-guidelines)
  - [Commit Message Format](#commit-message-format)
  - [Running Tests](#running-tests)
      - [notice : For Now We Dont Have Tests . its just PlaceHolder](#notice--for-now-we-dont-have-tests--its-just-placeholder)
  - [Code of Conduct](#code-of-conduct)

---

## Getting Started

* Fork the repo and create your branch from `main`.
* If you’ve added code that should be tested, add tests.
* Ensure the test suite passes (`make test`).
* Make sure your code lints (`go vet ./...` and `golangci-lint run`).
* Issue the PR and describe your change in detail.

## Bug Reports

* **Use the Issue Template.** Fill out all required fields so we can reproduce the problem quickly.
* Provide a **minimal, complete, and verifiable example**—redact any sensitive data.
* Label the issue as `bug`.

## Feature Requests

* Search existing issues to avoid duplicates.
* Explain **why** the feature is important and who will benefit.
* Label the issue as `enhancement`.

## Pull Requests

* We merge using **Squash & Merge**—one commit per feature.
* Reference the related issue in the PR description (`Fixes #123`).
* Ensure CI checks pass; otherwise explain why they fail.

## Coding Guidelines

* Use **Go 1.22** or later.
* Keep functions short and focused (≤ 50 LOC recommended).
* Document exported symbols with GoDoc comments.
* Prefer composition over inheritance; avoid global state.
* Format code with `gofmt` (or `goimports`).

## Commit Message Format

We follow the **Conventional Commits** specification:


```
<type>(scope?): <description>

<body>
```

Common `<type>` values:

* **feat** – new feature
* **fix** – bug fix
* **docs** – documentation only
* **test** – adding or refactoring tests
* **chore** – build process, CI, tooling
* **refactor** – code changes that neither fix a bug nor add a feature
* **style** – formatting, missing semi colons, etc; no code logic changes
* **perf** – performance improvements
* **revert** – reverts a previous commit
* **build** – changes that affect the build system or external dependencies
* **ci** – changes to CI configuration files and scripts

Example:

```
feat(api): add Telegram notification hook
```

## Running Tests

#### notice : For Now We Dont Have Tests . its just PlaceHolder 
```bash
make test      # unit tests 
make test-coverage  # generate coverage report
```

## Code of Conduct

We expect everyone to follow our [Code of Conduct](CODE_OF_CONDUCT.md). Instances of abusive behavior may be reported to **namiranet@proton.me**.
