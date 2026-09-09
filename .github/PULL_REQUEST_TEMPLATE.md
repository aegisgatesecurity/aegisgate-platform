## Description

<!-- Brief description of the change -->

## Type of Change
- [ ] Bug fix (non-breaking)
- [ ] New feature
- [ ] Security improvement
- [ ] Documentation update
- [ ] Refactor / cleanup

## Testing
- [ ] All tests pass (`go test ./...`)
- [ ] Coverage ≥ 78%
- [ ] `gofmt -l .` returns empty
- [ ] `go vet ./...` passes
- [ ] OPSEC scan passes (`tools/opsec-scan.sh`)

## Checklist
- [ ] DCO sign-off (`git commit -s`)
- [ ] No secrets / API keys committed
- [ ] No internal paths or documentation references
- [ ] Protected paths unchanged (pkg/ml/models/, training/, pkg/trust/, pkg/siem/)
