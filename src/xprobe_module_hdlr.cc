/* $Id: xprobe_module_hdlr.cc,v 1.7 2005/02/09 18:36:45 mederchik Exp $ */
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
#include "xprobe_module_hdlr.h"
#include "interface.h"
#include "cmd_opts.h"
#include "xpmodules/static_modules.h"
#include "log.h"

extern Interface *ui;
extern Cmd_Opts *copts;
extern XML_Log *xml;

int Xprobe_Module_Hdlr::load(void) {
	int cnt=1;
    xprobe_module_func_t *ptr;

    ui->msg("[+] Loading modules.\n");

    ptr = mod_init_funcs;
    while (ptr !=NULL && ptr->name !=NULL && ptr->func !=NULL) {
		if (!copts->mod_is_disabled(cnt++))
			add(ptr->func, ptr->name);
		ptr++;
	}
    return 1;

}

int Xprobe_Module_Hdlr::init(void) {

    for (unsigned int i=0; i< modlist.size(); i++) {
    modlist[i]->init();
    }

    return 1;
}

int Xprobe_Module_Hdlr::print(void) {

    ui->msg("[+] Following modules are loaded:\n");
	xml->log(XPROBELOG_MOD_SESS_START, "Loaded modules");
    for (unsigned int i=0; i<modlist.size(); i++) {
        ui->msg("[x] [%d] %s  -  %s\n", modlist[i]->get_id(),
			modlist[i]->get_name(), modlist[i]->get_desc());
		xml->log(XPROBELOG_MSG_MODULE, "%t%n%d%s", modlist[i]->get_type(),
				modlist[i]->get_name(), modlist[i]->get_id(), modlist[i]->get_desc());
	}
   ui->msg("[+] %i modules registered\n", modlist.size());
	xml->log(XPROBELOG_MOD_SESS_END, "End modules");
   return 1;
}
int Xprobe_Module_Hdlr::gather_info(Target *tg) {
    unsigned int i;

    for (i =0; i< modlist.size(); i++) {
        if(modlist[i]->get_type() == XPROBE_MODULE_INFOGATHER)
            xprobe_debug(XPROBE_DEBUG_MODULES, "Executing Module %s\n",
                         modlist[i]->get_name());
            modlist[i]->exec(tg, (OS_Matrix *)NULL); // INFORMATION GATHERING MODULES don't need OS
    }
    return 1;
}

int Xprobe_Module_Hdlr::exec(Target *tg, OS_Matrix *os) {

    /*
     We have two lists. pending modules (waiting for data) and
     executable modules

     1. We build executable module vector, from 'available' module
     vector by iterating through all available modules and checking if the module
     is ready to execute.

     2. if module is ready to execute, we move module to executable vector
      (if module is not ready to execute, we need to check if
      we have any other module that can provide that data. and if we find
      this module, we execute it).

     3. we sort executable vector

     4. we remove modules, that return information gain = 0

     5. if size of executable array is 0 - we terminate

     6. we execute module that is on the top of executable vector

     7. we remove executed module from executable vector

     8. we repeat

      */

    return 1;
}

int Xprobe_Module_Hdlr::fini(void) {
    vector <Xprobe_Module *>::iterator m_i;

    for (m_i=modlist.begin(); m_i!=modlist.end(); m_i++) {
        xprobe_debug(XPROBE_DEBUG_MODULES, "[+] Deinitializing module: [%i] %s\n",
                        (*m_i)->get_id(), (*m_i)->get_name());
        (*m_i)->fini();
        delete (*m_i);
        modlist.erase(m_i);
    }


    ui->msg("[+] Modules deinitialized\n");
    return 1;
}


int Xprobe_Module_Hdlr::add(int (*init_func)(Xprobe_Module_Hdlr *, char *), char *nm) {

    xprobe_debug(XPROBE_DEBUG_MODULES, "[+] adding %s via function: %p\n", nm, init_func);
    return(init_func(this, nm));
}

int Xprobe_Module_Hdlr::register_module(Xprobe_Module *mod) {

    mod_counter++;
    mod->set_id(mod_counter);
    modlist.push_back(mod);

    return 1;
}

void Xprobe_Module_Hdlr::add_keyword(int id, char *str) {
    string kwd(str);

    kwdlist.insert(pair<string, int>(kwd, id));
   	keywords++;
}

/* XXX: temp plug. Supposed to return module ptr which is registered for
 * keyword kwd
 */
Xprobe_Module *Xprobe_Module_Hdlr::find_mod(string &kwd) {
    map <string, int>::iterator kw_i;
    vector<Xprobe_Module *>::iterator m_i;

    kw_i = kwdlist.find(kwd);

    if (kw_i == kwdlist.end()) {
        xprobe_debug(XPROBE_DEBUG_CONFIG,
                     "[x] failed to lookup module on %s keyword\n", kwd.c_str());
        return NULL;
    }

    for (m_i=modlist.begin(); m_i!=modlist.end(); m_i++) {
        if ((*m_i)->get_id() == (*kw_i).second) {
            xprobe_debug(XPROBE_DEBUG_CONFIG,
                         "[x] keyword: %s handled by module: %s\n", kwd.c_str(),
                         (*m_i)->get_name());
            return (*m_i);
        }
    }
    ui->error("[x] failed to associate moudle id!\n");
    return NULL;
}

int Xprobe_Module_Hdlr::loaded_mods_num(int mod_type) {
    vector<Xprobe_Module *>::iterator m_i;
    int num = 0;

    for (m_i = modlist.begin(); m_i != modlist.end(); m_i++)
        if ((*m_i)->get_type() == mod_type) num++;

    /* sometimes os_test module handles multiple keywords */
    if (mod_type == XPROBE_MODULE_OSTEST && num < this->keywords)
        return this->keywords;

    return num;
}

int Xprobe_Module_Hdlr::modbyname(char *nm) {

    xprobe_module_func_t *ptr;
    int cnt = 0;

    ptr = mod_init_funcs;
    while (ptr !=NULL && ptr->name !=NULL && ptr->func != NULL) {
	    cnt++;
	    if (!strcasecmp(ptr->name, nm)) return cnt;
	    ptr++;
    }
    return -1;

}

void Xprobe_Module_Hdlr::display_mod_names(void) {

    xprobe_module_func_t *ptr;
    int cnt = 1;

    ptr = mod_init_funcs;
    while (ptr !=NULL && ptr->name !=NULL && ptr->func != NULL) {
/*
	    ui->msg("%s%c", ptr->name, cnt%4?'\t':'\n');
	    ptr++;
	    cnt++;
*/
		ui->msg("[%d] %s\n", cnt++, ptr->name);
		ptr++;

	}
}




Xprobe_Module_Hdlr::Xprobe_Module_Hdlr(void) {
    mod_counter = 0;
    keywords = 0;
}

Xprobe_Module_Hdlr::~Xprobe_Module_Hdlr(void) {
    /* do nothing now */
}

int Xprobe_Module_Hdlr::get_module_count() {
	int modcount=0;
	xprobe_module_func_t *ptr;

    ptr = mod_init_funcs;
    while (ptr !=NULL && ptr->name !=NULL && ptr->func != NULL) {
		modcount++;
		ptr++;
	}
	return modcount;
}
