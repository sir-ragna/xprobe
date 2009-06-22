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
extern OS_Name *oses;

/* we need a function to sort xprobe_module objects by pointer. */

bool compare_module(Xprobe_Module *lhs, Xprobe_Module* rhs) {
    /* we need to sort in descending order */
		return lhs->get_score() > rhs->get_score();
}

int Xprobe_Module_Hdlr::load(void) {
    xprobe_module_func_t *ptr;

    ui->msg("[+] Loading modules.\n");

    ptr = mod_init_funcs;
    while (ptr !=NULL && ptr->name !=NULL && ptr->func !=NULL) {
		if (!copts->is_mod_disabled(ptr->name))
			add(ptr->func, ptr->name);
		ptr++;
	}
    return 1;

}

int Xprobe_Module_Hdlr::init(void) {
    vector <Xprobe_Module *>::iterator m_i;

    for (m_i = modlist.begin(); m_i != modlist.end(); m_i++) {
    (*m_i)->init();
    (*m_i)->enable();
    }

    return 1;
}

int Xprobe_Module_Hdlr::print(void) {
    vector <Xprobe_Module *>::iterator m_i;

    ui->msg("[+] Following modules are loaded:\n");
	xml->log(XPROBELOG_MOD_SESS_START, "Loaded modules");
    for (m_i = modlist.begin(); m_i != modlist.end(); m_i++) {
        ui->msg("[x]  %s  -  %s\n", (*m_i)->get_name(), (*m_i)->get_desc());
		xml->log(XPROBELOG_MSG_MODULE, "%t%n%d%s", (*m_i)->get_type(),
				(*m_i)->get_name(), (*m_i)->get_id(), (*m_i)->get_desc());
	}
   ui->msg("[+] %i modules registered\n", modlist.size());
	xml->log(XPROBELOG_MOD_SESS_END, "End modules");
   return 1;
}
vector<Xprobe_Module *>::iterator   Xprobe_Module_Hdlr::mod_by_type(int type) {
    vector<Xprobe_Module *>::iterator m_i;
    for (m_i=modlist.begin(); m_i!=modlist.end(); m_i++) {
        if ((*m_i)->get_type() == type && !(*m_i)->is_disabled()) {
            return m_i;
        }
    }
    return modlist.end();
}
int Xprobe_Module_Hdlr::gather_info(Target *tg) {
    OS_Matrix *os = new OS_Matrix(this->loaded_mods_num(XPROBE_MODULE_INFOGATHER));
    vector <Xprobe_Module *>::iterator m_i;
    m_i = this->mod_by_type(XPROBE_MODULE_INFOGATHER);
    while(m_i != modlist.end()) {
        xprobe_debug(XPROBE_DEBUG_MODULES, "Executing Module %s\n",
                         (*m_i)->get_name());
        (*m_i)->exec(tg, os); // INFORMATION GATHERING MODULES don't need OS
        (*m_i)->disable();
        m_i = this->mod_by_type(XPROBE_MODULE_INFOGATHER);
    }
    delete os;
    return 1;
}
    /* */
    /*
    Our adaptive execution mechanism is very simple.

     0. we sort modules by their score

     1. We look through executable modules vector, we skip disabled modules.
     we search for module that is ready to execute
     or a module that requires some data which can be provided by other module.

     2. we execute this module, or data provider module.


     3. we set 'top matching os' for all the modules, so information gain(os) can be
     calculated properly.

     4. we may disable modules, that return information gain = 0

     5. if we don't execute any module during this iteration, we terminate

     6. we repeat

      */


int Xprobe_Module_Hdlr::exec(Target *tg, OS_Matrix *os) {
    vector <Xprobe_Module *>::iterator m_i;
    bool done;
    int iter;

    /* we set parameters for each module. so they can calculate their own scores */
    for (m_i=modlist.begin(); m_i!=modlist.end(); m_i++) {
        (*m_i)->set_totals(modlist.size(), keywords, oses->get_osnum());
        //cout << "module " << (*m_i)->get_name() << " t/r " << (*m_i)->get_total();
        //cout << "/" << (*m_i)->get_range() << "\n";
    }
    iter = 0;
    do {
        /* we sort modules */
        sort(modlist.begin(), modlist.end(), compare_module);
        done = false;
        m_i = modlist.begin();

        while (!done) {
            if (modlist.end() == m_i) {
                done = true;
                continue;
            }
            Xprobe_Module  * toexec = (*m_i);

            if (!(*m_i)->is_disabled()) {

                while (toexec != NULL && !(toexec)->enough_data(tg)) {
                    cout << toexec->get_name() << " has not enough data\n";
                    toexec = find_data_provider((*m_i)->missing_data(tg));
                }
                if (toexec == NULL) {
                    (*m_i)->disable();
                    continue; // try next module in list
                }
               // cout << "Executing " << toexec->get_name() <<
                //    " score " << toexec->get_score();
                //cout << "\n";
                toexec->exec(tg, os);
                toexec->disable();
                done = true;
                continue;
            }
            m_i++; // if first module was disabled, we just iterate

        }
        iter++;
        //cout << "iteration: " << iter << "\n";
        //cout << "suspected: " << oses->osid2char(os->get_top(0)) << "\n";

        if (m_i == modlist.end()) done = true;
        else done = false;

        /* tell all the modules that so far we are aiming at 'top_os'
         * so scores are ajusted */

        for (m_i=modlist.begin(); m_i!=modlist.end(); m_i++) {
            (*m_i)->set_topos(os->get_top(0));
        }
        /* for optimizaton, we may disable all the modules, whose information
         * gain would be there
         * but be careful not to disable any data collection modules, otherwise
         * it may impact execution of fingerprinting modules */

    } while (!done);

    return 1;
}

Xprobe_Module *Xprobe_Module_Hdlr::find_data_provider(string &d) {
    vector <Xprobe_Module *>::iterator m_i;
    Xprobe_Module *provider = NULL;

    for (m_i=modlist.begin(); m_i!=modlist.end(); m_i++) {
        if (!(*m_i)->is_disabled()) {
            if ((*m_i)->provides_data(d)) {
            return (*m_i);
            }
        }
    }

    return provider;
}
int Xprobe_Module_Hdlr::fini(void) {
    vector <Xprobe_Module *>::iterator m_i;

    for (m_i=modlist.begin(); m_i!=modlist.end(); m_i++) {
        xprobe_debug(XPROBE_DEBUG_MODULES, "[+] Deinitializing module: [%i] %s\n",
                        (*m_i)->get_id(), (*m_i)->get_name());
        (*m_i)->fini();
        delete (*m_i);
    }
    modlist.erase(modlist.begin(), modlist.end());


    ui->msg("[+] Modules deinitialized\n");
    return 1;
}


int Xprobe_Module_Hdlr::add(int (*init_func)(Xprobe_Module_Hdlr *, char *), char *nm) {

    xprobe_debug(XPROBE_DEBUG_MODULES, "[+] adding %s via function: %p\n", nm, init_func);
    return(init_func(this, nm));
}

int Xprobe_Module_Hdlr::register_module(Xprobe_Module* mod) {

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

bool Xprobe_Module_Hdlr::parse_keyword(int osid, string &kwd, string &val) {
    map <string, int>::iterator kw_i;
    vector<Xprobe_Module *>::iterator m_i;

    kw_i = kwdlist.find(kwd);

    if (kw_i == kwdlist.end()) {
        xprobe_debug(XPROBE_DEBUG_CONFIG,
                     "[x] failed to lookup module on %s keyword\n", kwd.c_str());
        return false;
    }

    for (m_i=modlist.begin(); m_i!=modlist.end(); m_i++) {
        if ((*m_i)->get_id() == (*kw_i).second) {
            xprobe_debug(XPROBE_DEBUG_CONFIG,
                         "[x] keyword: %s handled by module: %s\n", kwd.c_str(),
                         (*m_i)->get_name());
            int range = (*m_i)->parse_keyword(osid, kwd.c_str(), val.c_str());
            (*m_i)->inc_gain(osid, kwd ,val, range);
            return true;
        }
    }
    ui->error("[x] failed to associate module id!\n");
    return false;
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
