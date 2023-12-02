import os
import sqlite3
from typing import Optional

import ida_kernwin
import ida_hexrays
import ida_name
import idaapi
import idautils
import requests
from bs4 import BeautifulSoup

# Globals
DB_PATH = os.path.join(__file__, "commentator.db")
nimps = idaapi.get_import_module_qty()
decl_map = {}
func_map = {}
conn = None


# Funcs
#  https://github.com/mandiant/FIDL/blob/master/FIDL/decompiler_utils.py#L1062
def decompile(ea=None) -> Optional[idaapi.cfunc_t]:
    """This sets flags necessary to use this programmatically.

    :param ea: Address within the function to decompile
    :type ea: int
    :return: decompilation object
    :rtype: a :class:`cfunc_t`
    """

    if not ea:
        print("Please specify an address (ea)")
        return None

    try:
        cf = idaapi.decompile(
            ea=ea,
            flags=ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_NO_CACHE
        )
        cf.refresh_func_ctext()
    except ida_hexrays.DecompilationFailure as e:
        print("Failed to decompile @ {:X}".format(ea))
        cf = None

    return cf


# Referenced and improved upon from: https://github.com/mandiant/FIDL/blob/master/FIDL/decompiler_utils.py#L2105
def comment(ea, cmnt) -> bool:
    cf = decompile(ea)
    tl = idaapi.treeloc_t()
    tl.ea = ea
    # https://hex-rays.com/products/decompiler/manual/sdk/hexrays_8hpp.shtml#a219c95f85c085e6f539b8d3b96074aee
    for itp in [idaapi.ITP_SEMI, idaapi.ITP_CURLY1, idaapi.ITP_CURLY2, idaapi.ITP_COLON, idaapi.ITP_BRACE1,
                idaapi.ITP_BRACE2, idaapi.ITP_ASM, idaapi.ITP_ELSE, idaapi.ITP_DO, idaapi.ITP_CASE]:
        tl.itp = itp
        cf.set_user_cmt(tl, cmnt)
        cf.save_user_cmts()
        cf.__str__()  # trigger string representation, otherwise orphan comments aren't detected
        if not cf.has_orphan_cmts():
            return True
        cf.del_orphan_cmts()
    return False


def sanitize_name(n: str) -> str:
    t = ida_name.FUNC_IMPORT_PREFIX
    if n.startswith(t):
        n = n[len(t):]
    return n


def add_entry(func_name, decl):
    global conn
    if not conn:
        return
    c = conn.cursor()
    c.execute("INSERT INTO funcs VALUES (?, ?)", (func_name, decl))
    conn.commit()


def get_doc_link(func_name):
    url = f"https://learn.microsoft.com/api/search/rss?search={func_name}&locale=en-us&%24filter=%28category+eq+%27Documentation%27%29"
    r = requests.get(url)
    soup = BeautifulSoup(r.text, features='xml')
    ret = soup.find("item").find("link").text
    if not ret:
        return None
    return ret


def get_decl(func_name):
    ret = None
    c = conn.cursor()
    c.execute("SELECT decl FROM funcs where name = ?", (func_name,))
    e = c.fetchone()
    if e:
        ret = e[0]
    else:
        doc_link = get_doc_link(func_name)  # if we dont then fetch it
        if not doc_link:
            return None
        res = requests.get(doc_link)
        if not res:
            return None
        soup = BeautifulSoup(res.text, "html.parser")
        if not soup:
            return None
        ret = soup.find("code").text
    add_entry(func_name, ret)

    return ret


def cb(ea, name, ordinal):
    if not name:
        return True
    func_map[name] = ea
    return True


def populate_func_map():
    nimps = idaapi.get_import_module_qty()
    print("Populating func map")
    for i in range(0, nimps):
        idaapi.enum_import_names(i, cb)


# Some boiler plate
class Commentator(idaapi.plugin_t):
    flags = 0
    comment = (
        "Adds msdn annotation to all instances of the function in the entire idb")
    help = "Adds msdn annotation to functions"
    wanted_name = "MSDN commentator"
    wanted_hotkey = "Ctrl-Alt-S"

    def init(self):
        print("Initializing")
        global conn
        conn = sqlite3.connect(DB_PATH)
        populate_func_map()
        print("Loaded commentator")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        v = idaapi.get_current_viewer()
        iden, ok = idaapi.get_highlight(v)
        func_ea = idaapi.BADADDR

        if not ok:
            return

        iden = sanitize_name(iden)
        if iden in func_map.keys():
            func_ea = func_map[iden]
        if func_ea == idaapi.BADADDR:
            print("Function is not imported")
            return

        xrefs = idautils.CodeRefsTo(func_ea, 0)
        for xref in xrefs:
            comment(xref, get_decl(iden))
        ida_kernwin.refresh_idaview_anyway()

    def term(self):
        """DO NOTHING"""
        return


def PLUGIN_ENTRY():
    try:
        return Commentator()
    except Exception as err:
        import traceback
        print('Err: %s\n%s' % (str(err), str(traceback.format_exc())))
