// ============================================================================
// 无线 Portal 单测夹具 — 2026-09-03 实机抓取（scut-student，Dr.COM eportal）
//
// 数据来源：portal 页 a79.htm（用户 IP=10.197.179.90，wlanacip=192.168.53.174；
// 认证网关 10.197.183.254）、drcom/login 成功/失败响应、online_list 在线会话。
// 页面为 GBK，但协议值域全为 ASCII——夹具仅保留键值行（真实值原样），
// 另附少量多字节字节模拟 GBK 中文（标题/注释/msga），验证解析器不受编码干扰。
// ============================================================================

#ifndef WIFI_FIXTURES_H
#define WIFI_FIXTURES_H

#include <QByteArray>
#include <QString>

namespace WifiFixtures {

// ---- a79.htm 关键变量行（真实抓取值，值域原样保留）----
inline QByteArray a79Page()
{
    return QByteArrayLiteral(
        "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\">\n"
        "<html><head>\n"
        "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\">\n"
        "<title>\xD3\xC3\xBB\xA7\xB5\xC7\xC2\xBC\xD2\xB3</title>\n"    // GBK 中文"用户登录页"
        "<!--Dr.COMWebLoginID_0.htm-->\n"
        "<script type=\"text/javascript\">\n"
        "sv=0;sv1=0;v6='http://[::]:9002/v6                                     ';"
        "myv6ip='                                       ';v4serip='192.168.53.229' ;m46=0;"
        "v46ip='10.197.179.90'                         ;\n"
        "vid=0   ;mip=010197179090;Gno=0000;vlanid=\"0\"   ;AC=\"\";"
        "ipm=\"c0a835e5\";ss1=\"0010f3772b22\";ss2=\"0000\";ss3=\"0ac5b35a\";"
        "ss4=\"000000000000\";ss5=\"10.197.179.90\" ;ss6=\"192.168.53.229\" ;timet=1788394014; \n"
        "osele=0;//1=\xC2\xF2\xB5\xE5\xD6\xC8\n"                        // GBK 中文注释
        "domain='[::]';\n"
        "zxopt=0;//1\xCE\xAA\xC6\xD5\xCD\xA8\xB4\xF3\xBC\xDB\n"          // GBK 中文注释
        "hidm=0,hidn=0;\n"
        "aolno=1926;\n"
        "wopt=0;\n"
        "eport=-1,eclass=1;\n"
        "</script>\n"
        "<script type=\"text/javascript\">\n"
        "portalid='';portalname='';\n"
        "portalver='4.0';\n"
        "authexenable='0';\n"
        "authtype=1;\n"
        "authloginIP='';authloginport=801;authloginpath='/eportal/?c=ACSetting&a=Login';\n"
        "authloginparam='url=drappal';\n"
        "authuserfield='DDDDD';authpassfield='upass';\n"
        "terminalidentity=1;\n"
        "authlogouttype=1;authlogoutIP='';authlogoutport=801;\n"
        "authlogoutpath='/eportal/?c=ACSetting&a=Logout&ver=1.0';\n"
        "authlogoutparam='url=drappal';authlogoutpost='';\n"
        "querydelay=0;querytype=1;queryIP='';queryport=80;querypost='';querypath='/';queryparam='';\n"
        "authsuccess='Dr.COMWebLoginID_3.htm';authfail='Dr.COMWebLoginID_2.htm';\n"
        "isquery=0;authhost='';authoffpost='';\n"
        "charset='gb2312';exparam=0;\n"
        "</script>\n"
        "<script>\n"
        "var fileVersion=\"1745978612539\";\n"
        "</script>\n"
        "<script src=\"a41.js?version=1745978612539\"></script>\n"
        "</head>\n"
        "<body>\n"
        "</body>\n"
        "<script type=\"text/javascript\">\n"
        "	page.run();\n"
        "</script>\n"
        "</html>\n");
}

// ---- drcom/login 登录成功响应（08:05 实抓，删减无关字段保持最小）----
inline QByteArray loginSuccess()
{
    return QByteArrayLiteral(
        "dr9201({\"result\":1,\"aolno\":1904,\"m46\":0,\"v46ip\":\"10.197.179.90\","
        "\"sms\":0,\"ufee\":0,\"olno\":0,\"olmac\":\"000000000000\","
        "\"gid\":1,\"ispid\":0,\"opip\":\"0.0.0.0\","
        "\"ac0\":\"dGVzdGFjY291bnQ=\","
        "\"oltime\":4294967295,\"olflow\":4294967295,"
        "\"lip\":\"10.197.179.90\","
        "\"stime\":\"2026-09-03 08:05:26\",\"etime\":\"2026-09-03 08:07:57\","
        "\"uid\":\"testaccount\",\"sv\":0})");
}

// ---- drcom/login 凌晨时段拒绝响应（真实抓取）----
inline QByteArray loginNightBlocked()
{
    return QByteArrayLiteral(
        "dr1003({\"result\":0,\"wopt\":0,\"msg\":1,\"uid\":\"testaccount\","
        "\"hidm\":0,\"hidn\":-5,\"ss5\":\"10.197.183.251\",\"ss6\":\"192.168.53.229\","
        "\"vid\":0,\"ss1\":\"0010f3772b22\",\"ss4\":\"000000000000\","
        "\"cvid\":0,\"pvid\":0,\"hotel\":0,\"aolno\":1928,\"eport\":-1,\"eclass\":1,"
        "\"ubind\":\"mac1='',ty1=0\","
        "\"msga\":\"\xCA\xB1\xB6\xCE\xBD\xFB\xD6\xB9\xCA\xB9\xD3\xC3\"})"); // GBK"当前时段禁止使用"
}

// ---- drcom/login 冲突/错误账号响应（真实抓取）----
inline QByteArray loginUseridError()
{
    return QByteArrayLiteral(
        "dr9202({\"result\":0,\"wopt\":0,\"msg\":1,\"uid\":\"testaccount\","
        "\"hidm\":0,\"hidn\":-5,\"ss5\":\"10.197.179.90\",\"ss6\":\"192.168.53.229\","
        "\"vid\":0,\"ss1\":\"0010f3772b22\",\"ss4\":\"000000000000\","
        "\"cvid\":0,\"pvid\":0,\"hotel\":0,\"aolno\":1969,\"eport\":-1,\"eclass\":1,"
        "\"ubind\":\"mac1='',ty1=0\","
        "\"msga\":\"userid error2\"})");
}

// ---- drcom/login 密码错误响应（msga 为 GBK "账号密码错误！" 原始字节）----
inline QByteArray loginWrongPassword()
{
    return QByteArrayLiteral(
        "dr9004({\"result\":0,\"wopt\":0,\"msg\":1,\"uid\":\"testaccount\","
        "\"hidm\":0,\"hidn\":-6,\"ss5\":\"10.197.179.90\",\"ss6\":\"192.168.53.229\","
        "\"vid\":0,\"ss1\":\"0010f3772b22\",\"ss4\":\"000000000000\","
        "\"cvid\":0,\"pvid\":0,\"hotel\":0,\"aolno\":1971,\"eport\":-1,\"eclass\":1,"
        "\"ubind\":\"mac1='',ty1=0\","
        "\"msga\":\"\xD5\xCA\xBA\xC5\xC3\xDC\xC2\xEB\xB4\xED\xCE\xF3\xA3\xA1\"})");
}

// ---- online_list 无本机会话响应（未登录，list 空）----
inline QByteArray onlineListOffline()
{
    return QByteArrayLiteral(
        "dr9502({\"result\":1,\"msg\":\"\xBB\xF1\xC8\xA1\xD3\xC3\xBB\xD7\xD4\xDA\xCF\xDF\xD0\xC5\xCF\xA2\xB3\xC9\xB9\xA6\","
        "\"list\":[],\"total\":0});");
}

// ---- online_list 仅含他机会话（同网段其它设备，字段与在线响应同构）----
inline QByteArray onlineListForeign()
{
    return QByteArrayLiteral(
        "dr9503({\"result\":1,\"msg\":\"\xBB\xF1\xC8\xA1\xD3\xC3\xBB\xD7\xD4\xDA\xCF\xDF\xD0\xC5\xCF\xA2\xB3\xC9\xB9\xA6\","
        "\"list\":[{\"online_session\":33120,"
        "\"online_time\":\"2026-09-03 08:33:07\",\"online_ip\":\"10.197.179.91\","
        "\"online_mac\":\"d0e74f116a01\",\"time_long\":\"120\","
        "\"uplink_bytes\":\"0\",\"downlink_bytes\":\"10\",\"dhcp_host\":\"\",\"device_alias\":\"\","
        "\"nas_ip\":\"2922752192\",\"user_account\":\"otheruser@wifi\",\"is_owner_ip\":\"0\"}],"
        "\"total\":1});");
}

// ---- online_list 在线会话响应（08:31 实抓）----
inline QByteArray onlineListOnline()
{
    return QByteArrayLiteral(
        "dr9501({\"result\":1,\"msg\":\"\xBB\xF1\xC8\xA1\xD3\xC3\xBB\xA7\xD4\xDA\xCF\xDF\xD0\xC5\xCF\xA2\xB3\xB9\xB9\xA6\","
        "\"list\":[{\"online_session\":33306,"
        "\"online_time\":\"2026-09-03 08:25:37\",\"online_ip\":\"10.197.179.90\","
        "\"online_mac\":\"c40f089d34bf\",\"time_long\":\"1294\","
        "\"uplink_bytes\":\"0\",\"downlink_bytes\":\"29\",\"dhcp_host\":\"\",\"device_alias\":\"\","
        "\"nas_ip\":\"2922752192\",\"user_account\":\"testaccount@wifi\",\"is_owner_ip\":\"1\"}],"
        "\"total\":1});");
}

} // namespace WifiFixtures

#endif // WIFI_FIXTURES_H
