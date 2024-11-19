#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0

from os import path
from lib.py import ksft_run, ksft_exit
from lib.py import NetDrvEpEnv
from lib.py import bkg, cmd, wait_port_listen


def test_zcrx(cfg) -> None:
    cfg.require_v6()

    rx_cmd = f"{cfg.bin_remote} -6 -s -p 9999 -i {cfg.ifname} -q 13"
    tx_cmd = f"{cfg.bin_local} -6 -c -h {cfg.remote_v6} -p 9999 -l 12840"

    with bkg(rx_cmd, host=cfg.remote, exit_wait=True):
        wait_port_listen(9999, proto="tcp", host=cfg.remote)
        cmd(tx_cmd)


def main() -> None:
    with NetDrvEpEnv(__file__) as cfg:
        cfg.bin_local = path.abspath(path.dirname(__file__) + "/../../../drivers/net/hw/iou-zcrx")
        cfg.bin_remote = cfg.remote.deploy(cfg.bin_local)

        ksft_run(globs=globals(), case_pfx={"test_"}, args=(cfg, ))
    ksft_exit()


if __name__ == "__main__":
    main()
