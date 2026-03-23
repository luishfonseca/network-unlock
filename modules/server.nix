inputs: {
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.networkUnlock.server;
in {
  options.networkUnlock.server = with lib; {
    enable = mkEnableOption "network unlock server.";
    package = mkPackageOption inputs.self.packages.${pkgs.stdenv.system} "networkUnlock" {};
    ttl = mkOption {
      type = types.int;
      default = 300;
    };
    port = mkOption {
      type = types.port;
      default = 9745;
    };
    internal = mkOption {
      type = types.str;
      description = "Internal IP address to listen for registration requests.";
    };
    external = mkOption {
      type = types.str;
      default = cfg.public;
      description = "External IP address to listen for unlock requests. Override for NAT.";
    };
    public = mkOption {
      type = types.str;
      description = "External IP address as seen by peer.";
    };
    openFirewall = mkEnableOption "open the required firewall port.";
  };

  config = lib.mkIf cfg.enable {
    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [cfg.port];

    systemd.services.network-unlock = {
      wantedBy = ["multi-user.target"];
      wants = ["network.target"];
      after = ["network.target"];
      serviceConfig = {
        DynamicUser = true;

        # Needed to freebind
        AmbientCapabilities = "cap_net_raw";
        CapabilityBoundingSet = "cap_net_raw";

        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateDevices = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        MemoryDenyWriteExecute = true;
        RestrictNamespaces = true;

        ExecStart = lib.concatStringsSep " " [
          "${cfg.package}/bin/network-unlock serve"
          "--internal ${cfg.internal}"
          "--external ${cfg.external}"
          "--public ${cfg.public}"
          "--port ${toString cfg.port}"
          "--ttl ${toString cfg.ttl}s"
        ];
        Restart = "on-failure";
      };
    };
  };
}
