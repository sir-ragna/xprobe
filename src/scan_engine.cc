/* $Id: scan_engine.cc,v 1.8 2005/02/08 20:00:35 mederchik Exp $ */
/*
** Copyright (C) 2001 Fyodor Yarochkin <fygrave@tigerteam.net>,
**                    Ofir Arkin       <ofir@sys-security.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/


#include "xprobe.h"
#include "scan_engine.h"
#include "interface.h"
#include "targets_list.h"
#include "xprobe_module_hdlr.h"
#include "os_matrix.h"
#include "config_set.h"
#include "cmd_opts.h"
#include "log.h"

extern Targets_List *targets;
extern Xprobe_Module_Hdlr   *xmh;
extern Interface *ui;
extern OS_Name *oses;
extern Config_Set *cfg;
extern Cmd_Opts *copts;
extern XML_Log *xml;

int Scan_Engine::init(void) {
    ui->msg("[+] Initializing scan engine\n");
    return 1;
}

int Scan_Engine::run(void) {
    Target *tg;
    Xprobe::Timeval rtt;
    ui->msg("[+] Running scan engine\n");
    while((tg = targets->getnext()) != NULL) {
        tg->show_route(cfg->show_route());
        tg->set_udp_ports(cfg->get_udp_ports());
        tg->set_tcp_ports(cfg->get_tcp_ports());
        tg->set_tcp_toscan(copts->get_tcp_ports_to_scan());
        tg->set_udp_toscan(copts->get_udp_ports_to_scan());
        tg->generate_sig(copts->generate_sig());
        xml->log(XPROBELOG_TG_SESS_START, "%a", inet_ntoa(tg->get_addr()));

        if (copts->is_rtt_forced()) {
            rtt = copts->get_timeout(); // then we override
            tg->set_rtt(rtt);
            ui->msg("[+] RTT forced: %.5f sec\n",
                                  (double)tg->get_rtt());
        }
        if (copts->do_portscan()) {
            ui->msg("[+] Initial Information Gathering forced");
            tg->gather_info();
        }
        tg->scan();
        xml->log(XPROBELOG_TG_SESS_END, "done with target");
    }

    return 1;
}

int Scan_Engine::fini(void) {
    ui->msg("[+] Cleaning up scan engine\n");

    return 1;
}

