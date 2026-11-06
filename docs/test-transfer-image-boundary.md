# Gateway image boundary test transfer

Source: `FyberLabs/panopticon` revision
`2cd00fd9a7ebb950999571a81be7cb0a24d9264e`,
`products/hypermesh-gateway/tests/test_no_seed_import.py`,
`test_gateway_dockerfile_does_not_copy_hypermesh_service_seed`.

The source runtime-import tests already execute against source, wheel and rebuilt
sdist. Retain the formerly missing Dockerfile assertion in `tests_tools`, run by
the package lane. The three prohibitions are unchanged. The positive ticket
assertion now requires the extracted image's verified-wheel COPY/install instead
of the obsolete monorepo ticket-source COPY.

The existing networkless final-image check additionally requires the installed
public ticket package and proves both plane implementation and private billing
are absent. No WireGuard peer, host or provider is contacted. No image is
published by this check.
