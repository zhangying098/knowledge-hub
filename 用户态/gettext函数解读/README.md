## `gettext` 函数解读
### 一、简介
**提供国际化 （I18N） 和本地化 （L10N） 服务**。用于在多语言环境下获取相应的翻译文本。它的主要功能是根据给定的字符串文本返回正确的翻译文本，以便在不同的语言环境中使用相同的代码。

该函数会在当前环境的翻译文件中查找这个字符串对应的翻译文本。如果找到了对应的翻译文本，则返回该文本；否则，返回原始的字符串。

## 二、DEMO 示例
### 目录结构
```shell
demo
├── build.sh
├── gettextdemo.c
└── locale 
    ├── en_US
    │   └── LC_MESSAGES
    │       ├── dragon.mo
    │       └── dragon.po
    └── zh_CN
        └── LC_MESSAGES
            ├── dragon.mo
            └── dragon.po
```
### `gettextdemo.c`解析
```c
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
```
### `build.sh` 解析
```shell
gcc -Wall -g -o gettextdemo gettextdemo.c
# -k_ 参数表示要提取以下划线 _ 开头的函数调用作为翻译字符串的标识符
xgettext -k_ gettextdemo.c -o ./locale/zh_CN/LC_MESSAGES/dragon.po
xgettext -k_ gettextdemo.c -o ./locale/en_US/LC_MESSAGES/dragon.po

# 需要修改 po 文本的字符编码及类型为 UTF-8 
sed -i 's/Content-Type: text\/plain; charset=CHARSET/Content-Type: text\/plain; charset=UTF-8/g' ./locale/zh_CN/LC_MESSAGES/dragon.po
sed -i 's/Content-Type: text\/plain; charset=CHARSET/Content-Type: text\/plain; charset=UTF-8/g' ./locale/en_US/LC_MESSAGES/dragon.po

# 指定翻译后的语句
sed -i 's/msgstr "*"/msgstr "你好世界\\n"/g' ./locale/zh_CN/LC_MESSAGES/dragon.po
sed -i 's/msgstr "*"/msgstr "hello world\\n"/g' ./locale/en_US/LC_MESSAGES/dragon.po

# 生成对应的 mo 文件
msgfmt -o ./locale/zh_CN/LC_MESSAGES/dragon.mo ./locale/zh_CN/LC_MESSAGES/dragon.po
msgfmt -o ./locale/en_US/LC_MESSAGES/dragon.mo ./locale/en_US/LC_MESSAGES/dragon.po
```
### `mo` 文本解析
**po 格式 - 以下是对每个字段的解释：**
- msgid：原始文本的字符串
- msgstr：对应的翻译文本字符串
- Project-Id-Version：项目版本信息
- Report-Msgid-Bugs-To：报告错误信息的联系方式
- POT-Creation-Date：POT 文件生成日期和时间
- PO-Revision-Date：PO 文件的修订日期和时间
- Last-Translator：最后一个翻译人员的姓名和电子邮件地址
- Language-Team：语言团队的联系方式
- Language：当前翻译的语言
- MIME-Version：MIME 版本号
- Content-Type：内容类型，指明文本的字符编码及类型
- Content-Transfer-Encoding：内容传输编码

开发者根据需要将原始文本添加到 msgid 字段中，并在对应的 msgstr 字段中填写相应的翻译文本。

```shell
# SOME DESCRIPTIVE TITLE.
# Copyright (C) YEAR THE PACKAGE'S COPYRIGHT HOLDER
# This file is distributed under the same license as the PACKAGE package.
# FIRST AUTHOR <EMAIL@ADDRESS>, YEAR.
#
#, fuzzy
msgid ""
msgstr ""
"Project-Id-Version: PACKAGE VERSION\n"
"Report-Msgid-Bugs-To: \n"
"POT-Creation-Date: 2024-01-06 23:36+0800\n"
"PO-Revision-Date: YEAR-MO-DA HO:MI+ZONE\n"
"Last-Translator: FULL NAME <EMAIL@ADDRESS>\n"
"Language-Team: LANGUAGE <LL@li.org>\n"
"Language: \n"
"MIME-Version: 1.0\n"
"Content-Type: text/plain; charset=UTF-8\n"
"Content-Transfer-Encoding: 8bit\n"

#: gettextdemo.c:27
#, c-format
msgid "Hello world!\n"
msgstr "你好世界\n"
```
### 参考资料
https://www.gnu.org/software/gettext/

https://www.gnu.org/software/gettext/manual/gettext.html#xgettext-Invocation