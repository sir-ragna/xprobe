/* $Id: HTTP_Mod.h,v 1.2 2003/04/22 20:00:54 fygrave Exp $ */
/*
** Copyright (C) 2001 Fyodor Yarochkin <fygrave@tigerteam.net>,
**                    Ofir Arkin       <ofir@sys-security.com>
p*
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

#ifndef HTTP_Mod_H
#define HTTP_Mod_H

#include "xprobe.h"
#include "xprobe_module.h"


class HTTP_Mod: public Xprobe_Module {
    private:
    public:
        HTTP_Mod(void);
        ~HTTP_Mod(void) { return; }
        int init(void);
        int parse_keyword(int, char *, char *);
        int exec(Target *, OS_Matrix *);
        int fini(void);
        int parse_keyword(int, const char *, const char *);
};

#endif /* HTTP_Mod_H */
