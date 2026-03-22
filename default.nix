{buildGoModule}:
buildGoModule rec {
  pname = "network-unlock";
  version = "0.1.0";
  src = ./.;
  vendorHash = "sha256-4i7BX+Ox2Brvz7Un8a5N2wlNlG2tDT33+VtzJ1H48FA=";

  ldflags = ["-s -w -X main.Version=${version}"];
  env.CGO_ENABLED = 0;

  meta.mainProgramz = pname;
}
