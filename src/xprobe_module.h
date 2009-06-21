/* $Id: xprobe_module.h,v 1.6 2005/02/08 20:00:35 mederchik Exp $ */
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

#ifndef XPROBE_MODULE_H
#define XPROBE_MODULE_H

#include "xprobe.h"
#include "target.h"
#include "xplib/xp_sha1.h"
//#include "module_data.h"
#include "os_matrix.h"
#include "usi++/usi++.h"
//#include <string>

using namespace std;

#define XPROBE_MODULE_ALIVETEST     1
#define XPROBE_MODULE_OSTEST        2
#define XPROBE_MODULE_INFOGATHER	3
class OsIdPair {
private:
    vector <int> osid;
    int range;
    string val;
public:
    OsIdPair(void) {
    }
    OsIdPair(int i, string & s, int r) {
        this->osid.push_back(i);
        this->val = this->low(s);
        if (r < 1) {
            cout << "Error! value " << s << " given range is " << r << "default to 1\n";
            r = 1;
        }
        this->range = r;
    }
    static string &low(string & s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }
    void add_osid(int i) {
        osid.push_back(i);
    }
    OsIdPair & operator= (const OsIdPair &rhs) {
        this->val = rhs.val;
        this->osid = rhs.osid;
    return *this;
    }

    bool operator== (const OsIdPair &rhs) {
        return (val.compare(rhs.val) == 0);
    }
    bool operator<(const OsIdPair &rhs) {
        return this->osid.size() < rhs.osid.size();
    }
    bool hasid(int o) {
        if (find(osid.begin(), osid.end(), o)!= osid.end()) {
        return true;
        }
        return false;
    }
    int total(void) {
        return osid.size();
    }
    int get_range() {
        return range;
    }
};

class KeywGain {
private:
    vector <OsIdPair> values;
    string key;
public:
    KeywGain(string & k) {
        key = OsIdPair::low(k);
    }
    bool iskey( string &k) {
        return (key.compare(k) == 0);
    }
    void add_gain(int osid, string & s, int r) {
         OsIdPair p = OsIdPair(osid, s, r);
        vector<OsIdPair>::iterator o_i;
        for (o_i = values.begin(); o_i != values.end(); o_i++) {
            if ((*o_i) == p) {
                (*o_i).add_osid(osid);
                return;
            }
        }
        values.push_back(p);
    }
    int total() {
    /* this is how many signatures in total this keyword covers */
        int tl = 0;
        vector<OsIdPair>::iterator o_i;
        for (o_i = values.begin(); o_i != values.end(); o_i++) {
            tl += (*o_i).total();
        }
        return tl;
    }
    int range(int osid) {
        /* how different the values can be. in numbers */
        /* Currently we assume that all possible values are represented in signature
         * file. However,
         * we may need to introduce special semantics in keyword name to correct this
         * logic. */
        vector<OsIdPair>::iterator o_i;
        for (o_i = values.begin(); o_i != values.end(); o_i++) {
            if((*o_i).hasid(osid)) {
                return (*o_i).get_range();
            }
        }

        return 0; // means this keyword has no value for asked signature
    }
    int similarTo(int osid) {
        /* how many other osids have the same value */
        vector<OsIdPair>::iterator o_i;
        for (o_i = values.begin(); o_i != values.end(); o_i++) {
            if((*o_i).hasid(osid)) {
            /* each keyword can only have one value for a particular OS! */
                return (*o_i).total();
            }

        }
        return 0; /* this keyword doesn't have any sig for this OS fingerprint */
    }
};

class Xprobe_Module {
    private:
        vector<KeywGain> gain;
        string name;
        string description;
        int mod_id;
        int mod_type;
		bool enabled;
        vector<string> required;
        vector<string> provided;
		virtual void generate_signature(Target *, ICMP *, ICMP *) { return; }
		virtual void generate_signature(Target *, TCP *, TCP *) { return; }
        int total_keywords;
        int top_osid;
        int total_modules;
        int total_sigs;
   public:
    void inc_gain(int osid, string key, string val, int range) {
        vector <KeywGain>::iterator k_i;
        for (k_i = gain.begin(); k_i != gain.end(); k_i++) {
            if ((*k_i).iskey(key)) {
                (*k_i).add_gain(osid, val, range);
                return;
            }
        }
        KeywGain kw = KeywGain(key);
        kw.add_gain(osid, val, range);
        gain.push_back(kw);
    }
    void set_desc(const char *nm) { description = nm; }
    const char *get_desc(void) { return description.c_str(); }
    void set_name(const char *nm) { name = nm; }
    const char* get_name(void) { return name.c_str(); }
    string& get_sname(void) { return name; }
    void set_id(int id) { mod_id = id; }
    int get_id(void) { return mod_id; }
    void set_type(int type) { mod_type = type; }
    int get_type(void) { return mod_type; }


    Xprobe_Module(void) { set_name((const char *)"noname"); set_desc("No description is given");}
    Xprobe_Module(int type, const char *nm, const char *desc) { set_type(type); set_name(nm); set_desc(desc); }
/* module can be enabled or disabled. and is desabled after execution */
	void enable(void) { enabled = true; }
	void disable(void) { enabled = false; }
	bool is_disabled(void) { return (enabled == false);};
/* copy operator */
    Xprobe_Module& operator=(Xprobe_Module& rhs) {
        this->set_id(rhs.get_id());
        this->set_type(rhs.get_type());
        this->set_name(rhs.get_name());
        this->set_desc(rhs.get_desc());
        if (rhs.is_disabled()) {
        this->disable();
        } else {
        this->enable();
        }
        return *this;
    }
    /* each module needs to know how many modules are there. how many keywords registered.
     * and what is the current top os id... these values are set by module handler.
     * we have some debugging messages to ensure that module handler mistakes
     * can be detected.
     */
    float get_firstscore() {
        if (gain.size() == 0) {
            return 0;
        }
        if (this->total_modules == 0 || this->total_keywords == 0 || this->total_sigs == 0) {
            cout << "BUG: total_modules or total_keywords are not set. cant score!\n";
            cout << total_modules << " " << total_keywords << " " << total_sigs << "\n";
            return 1;
        }
        return ((float)this->get_total() / (float)this->total_sigs);
    }
    void set_totals(int m, int k, int s) {
    this->total_modules = m;
    this->total_keywords = k;
    this->total_sigs = s;
    this->top_osid  = -1; /* initially it is -1. so we calculate score differently
                             first time */
    }
    void set_topos(int osid) {
    this->top_osid = osid;
    }
	float get_score() {
        /* if we haven't executed any scans yet. we don't know
         * what os matched last time. in this case all modules are
         * equivalent and we need to score them based on how many sigs
         * we have for each of the modules in sig file. the more the merrier ;-) */
        if (this->top_osid == -1 || this->total_sigs == 0) return get_firstscore();

        if (gain.size() == 0) {
            return 0; /* this module score 0, because it doesn't have any sigs
                         so it will only run if requested by other modules, or is
                         executed as part of forced information gathering process.
                       */
        }
        float similar = 0;
        /* we calculate how many osIds ths module can make us similar to */
        vector<KeywGain>::iterator k_i;
        for (k_i = gain.begin(); k_i != gain.end(); k_i++) {
            similar = (similar + (*k_i).similarTo(top_osid));
        }
        //cout << " probability " << similar/this->total_sigs << "\n";
        return ((float)similar/(float)this->total_sigs);
    }
    int get_total() {
    /* how many sigs in total we have for this module. we can calculate module freq */
        int total = 0;
        vector<KeywGain>::iterator k_i;
        for (k_i = gain.begin(); k_i != gain.end(); k_i++) {
            if (total < (*k_i).total())
                total = (*k_i).total();
        }
        return total;
    }
    bool provides_data(string &s) {
        vector<string>::iterator s_i;
        if (provided.size() == 0)
            return false;
        for(s_i = provided.begin(); s_i != provided.end(); s_i++) {
            if ((*s_i).compare(s) == 0)
                return true;
        }
        return false;
    }
    bool enough_data(Target *tg) {
        vector<string>::iterator s_i;
        if (required.size() == 0)
            return true;
        for(s_i = required.begin(); s_i != required.end(); s_i++) {
            if (!tg->has_data((*s_i)))
                return false;
        }
        return true;
    }
    string & missing_data(Target *tg) {
        vector<string>::iterator s_i;
        for(s_i = required.begin(); s_i != required.end(); s_i++) {
            if (!tg->has_data((*s_i)))
                return (*s_i);
        }
        cout << "badly called missing_data!!\n";
        /* we never should get to this point. if we do. it means
         * we were called without first checking if target has enough data
         */
        return (*s_i);
    }
    void add_provides(string s) {
        provided.push_back(s);
    }
    void add_requires(string s) {
        required.push_back(s);
    }
    void add_provides(char *s) {
        add_provides(string(s));
    }
    void add_requires(char *s) {
        add_requires(string(s));
    }
    virtual ~Xprobe_Module(void) { return; }
    /* these to be overriden */
    virtual int init(void) =0;
    virtual int parse_keyword(int, const char *, const char *) =0;
    virtual int exec(Target *, OS_Matrix *) =0;
    virtual int fini(void) =0;
};

#endif /* XPROBE_MODULE */

