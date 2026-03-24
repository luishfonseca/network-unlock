inputs: {
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.networkUnlock.client;
in {
  options.networkUnlock.client = with lib; {
    enable = mkEnableOption "network unlock client";
    package = mkPackageOption inputs.self.packages.${pkgs.stdenv.system} "networkUnlock" {};
    units = mkOption {
      type = types.listOf types.str;
      default = [];
      example = ["tailscaled.service"];
      description = "Systemd units needed for internal network connectivity";
    };
    port = mkOption {
      type = types.port;
      default = 9745;
      description = "Port for the key services.";
    };
    self = {
      internal = mkOption {
        type = types.str;
        description = "Internal IP address to register with.";
      };
      public = mkOption {
        type = types.str;
        description = "External IP address as seen by peer.";
      };
    };
    peer = {
      internal = mkOption {
        type = types.str;
        description = "Internal IP address to register.";
      };
      public = mkOption {
        type = types.str;
        description = "Public IP address to request keys.";
      };
    };
    luks = {
      crypt = mkOption {
        type = types.str;
        example = "root_crypt";
        description = "Device to unlock. Must match the name under /dev/mapper.";
      };
      key = mkOption {
        type = types.str;
        example = "/recovery/root.key";
        description = "Management key. Must be on encrypted volume.";
      };
      slot = mkOption {
        type = types.int;
        default = 7;
        description = "Slot to enroll the ephemeral key to.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = config.boot.initrd.systemd.network.enable;
        message = "Network unlock requires systemd network in initrd.";
      }
      {
        assertion = config.boot.initrd.systemd.network.networks != {};
        message = "Network unlock requires at least one network configured.";
      }
    ];

    systemd.services = {
      # ExecStart=cleanup, ExecStop=prepare looks backwards but is intentional:
      # on boot (start), we clean up the ephemeral key that was just used.
      # On shutdown (stop), we prepare credentials for the *next* boot.
      # RemainAfterExit keeps the unit "active" in between so stop runs on shutdown.
      network-unlock-prepare = {
        wantedBy = ["multi-user.target"];
        wants = cfg.units;
        after = cfg.units;
        path = [pkgs.cryptsetup];
        unitConfig.RequiresMountsFor = ["/boot" "/recovery"];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = lib.concatStringsSep " " [
            "${cfg.package}/bin/network-unlock cleanup"
            "--luks-crypt /dev/mapper/${cfg.luks.crypt}"
            "--luks-key ${cfg.luks.key}"
            "--luks-slot ${toString cfg.luks.slot}"
          ];
          ExecStop = lib.concatStringsSep " " [
            "${cfg.package}/bin/network-unlock prepare"
            "--self-internal ${cfg.self.internal}"
            "--self-public ${cfg.self.public}"
            "--peer-internal ${cfg.peer.internal}"
            "--port ${toString cfg.port}"
            "--luks-crypt /dev/mapper/${cfg.luks.crypt}"
            "--luks-key ${cfg.luks.key}"
            "--luks-slot ${toString cfg.luks.slot}"
          ];
        };
      };
    };

    fileSystems."/boot".neededForBoot = true;

    boot.initrd = let
      keyFile = "/run/unlock/fifo";
    in {
      luks.devices.${cfg.luks.crypt} = {
        inherit keyFile;
      };

      systemd = {
        network.wait-online.anyInterface = true;
        initrdBin = [cfg.package];

        services.network-unlock = {
          before = ["systemd-cryptsetup@${cfg.luks.crypt}.service"];
          wants = ["systemd-networkd-wait-online.service"];
          after = ["systemd-networkd-wait-online.service"];
          wantedBy = ["initrd.target"];
          unitConfig = {
            DefaultDependencies = false;
            RequiresMountsFor = "/sysroot/boot";
          };
          serviceConfig = {
            Type = "notify";
            ExecStart = lib.concatStringsSep " " [
              "${cfg.package}/bin/network-unlock unlock"
              "--peer-public ${cfg.peer.public}"
              "--port ${toString cfg.port}"
              "--fifo ${keyFile}"
            ];
          };
        };
      };
    };
  };
}
