# TODO

- [x] Create CRD
- [x] Generate TS Classeses
- [x] Reconile CRDs
- [x] Improve build for UDS Package to deploy CRDs first and not overwrite
- [x] Scope RBAC
- [x] Add CRD statuses
- [x] Use validation warnings in the event mode is not enforce
- [ ] Bundle
- [ ] Add unit tests
- [ ] add e2e tests
- [x] annotate pods
- [ ] UDS Package
- [x] Implement SBOM Component Scanning against denied components
- [x] Make sure public key is only read once
- [x] Read Zarf registry info only once (Already caches)
- [x] Do registry config only once (Uses loadZarfRegistryInfo)
- [x] Remove duplicated types in generated
- [x] Watch for removal of SbomEnforce and SigEnforce and update local cache
- [x] Ensure only one SBOM and Sig exist per namespace
- [x] Watch for Zarf State Secret and if changes update it (N/A - ignoring Zarf namespace)

