# DXVK DLL provenance

The DLLs in this directory are the **exact binaries shipped inside
GE-Proton10-31**. They are not from an upstream DXVK release tarball.

## Source

- GE-Proton release: <https://github.com/GloriousEggroll/proton-ge-custom/releases/tag/GE-Proton10-31>
- Release tarball: <https://github.com/GloriousEggroll/proton-ge-custom/releases/download/GE-Proton10-31/GE-Proton10-31.tar.gz>
- Inside the tarball:
  `GE-Proton10-31/files/lib/wine/dxvk/x86_64-windows/d3d11.dll`
  `GE-Proton10-31/files/lib/wine/dxvk/x86_64-windows/dxgi.dll`
- GE-Proton's `dxvk` submodule at that tag is pinned to upstream doitsujin/dxvk
  commit `3731c2f5b67942f5eafbb12e7444b787dfb12775`
  (<https://github.com/doitsujin/dxvk/tree/3731c2f5b67942f5eafbb12e7444b787dfb12775>).
  GE-Proton's `patches/` at that tag contains no DXVK patches, so the sources
  are upstream.
- The version strings embedded in the DLLs are `v2.7.1-451-g3731c2f5` and
  `v2.7.1-4H` (`git describe` over the pinned submodule).

## Verified hashes (SHA-256)

| File | Hash |
|---|---|
| `x86_64/d3d11.dll` | `3ba898530288520aedfe0876c6a98939c2684af1792c720d259f3b1d30393296` |
| `x86_64/dxgi.dll`  | `793f542bd38669757c59f87c7f188e30bb51f01f86a7177a4c6a1fe3fff8090f` |
| `i386/d3d11.dll`   | `8550dfd4d525185bd8df91989e2deab31c8253023d5a89b0c1c22e4152242f58` |
| `i386/dxgi.dll`    | `a1ad03f8a1c359686bcd7f98e432cc8ae837b44abf4387ec298ebd48e0b20146` |

`src/proton.rs` checks the two x86-64 hashes on every launch and rewrites the
DLLs if they are missing or modified. The i386 copies are kept for reference
only; the game and its Vuplex child processes are x86-64.

## Why not an upstream 2.7.1 tarball

The official `dxvk-2.7.1.tar.gz` release contains different builds
(`d3d11.dll` `523da2cd765dd51d99fe1644b24f9ee7ee6247e4c98953bcc449ce84cd303405`,
`dxgi.dll` `ec02eb37620ff52361cb45376a4611fc4210d96e71d0363f1cc9807f151c01be`)
and was tested **not** to restore Vuplex frames. The pinned GE build is 451
commits past the 2.7.1 tag, so it has no standalone release asset; extracting
it from the GE-Proton10-31 tarball on every dependency install is impractical.

## Replacing these files

Extract the two DLLs from the GE-Proton10-31 tarball (paths above), or rebuild
the pinned dxvk commit with the same MinGW toolchain, then update the hashes in
`src/proton.rs`. Do not substitute a generic DXVK release.

## License

DXVK is distributed under the zlib/libpng license; see `LICENSE`.
