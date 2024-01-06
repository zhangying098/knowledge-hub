#include <stdio.h>
#include <locale.h>
#include <libintl.h>

#define _(string) gettext(string)
#define N_(string) string

int main()
{
    /*
        指定翻译方向，和文本域路径 en_US / zh_CN 相关
    */
    // setlocale(LC_ALL, "en_US.UTF-8");
    setlocale(LC_ALL, "zh_CN.UTF-8");
    /*
        功能：设置文本域目录（文本域：mo文件）
        param1：缺省 .mo 后缀的 xxx.mo 文件名
        param2: xxx.mo 文件所在的基目录
    */
    bindtextdomain("dragon", "locale");
    /*
        功能：设置需要使用的文本域，文本域经过 bindtextdomain() 指定.
              gettext 库可找到相应的mo文件并操作它们.
    */
    textdomain("dragon");

    printf(_("Hello world!\n"));
    printf(N_("Hello world!\n"));
    return 0;
}